rule powershell_ren {
  strings:
    $a = "powershell" nocase

  condition:
    $a
}