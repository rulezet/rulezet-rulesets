rule tibetan_indecent_powershell {
  meta:
    author = "Matt Brooks, @cmatthewbrooks"

  strings:
    $decents1 = "$indecentID" ascii wide
    $decents2 = "$decentID" ascii wide
    $decents3 = "powershell" ascii wide nocase

  condition:
    all of them
}