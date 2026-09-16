rule XProtect_MACOS_71915a8 {
  meta:
    description = "MACOS.71915a8"

  strings:
    $shebang = "#!"
    $a       = "zsh"
    $b       = "\\U00000"
    $c       = "${"
    $d       = "rev)"

  condition:
    filesize < 10KB and $shebang at 0 and $a and #b > 15 and #c > 100 and $d
}