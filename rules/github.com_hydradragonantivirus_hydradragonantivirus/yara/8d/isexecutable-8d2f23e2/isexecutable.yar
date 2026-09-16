rule isExecutable {
  meta:
    author      = "73mp74710n"
    description = "Yara rule to check for unobfuscated rat created with njrat"

  strings:
    $MZ = { 4D 5A 90 00 }
    $PE = { 50 45 00 00 }

  condition:
    $MZ at 0 and $PE

}