import "pe"
rule ASProtect_v1_1_MTEc {
  strings:
    $a0 = { 90 60 E8 1B ?? ?? ?? E9 FC }

  condition:
    $a0 at pe.entry_point
}