rule tibetan_indecent_rtf_meta {
  meta:
    author = "Matt Brooks, @cmatthewbrooks"

  strings:
    $operator = "{\\operator Windows \\'d3\\'c3\\'bb\\'a7}"

  condition:
    any of them
}