rule infected_language_ru_082218 {
  meta:
    description = "shell5 - file master-language_ru.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2018-08-23"
    hash1       = "7d97b8ce81e08ab2ea6ee043f32a9c91a250baf2e356630c89708dfbe3c79e32"

  strings:
    $s1 = "$x($_POST['tb_id']);" fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 2KB and
      (all of them)
    ) or (all of them)
}