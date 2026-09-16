rule MD5_constants__32_lil_AND_ {
  strings:
    $a0 = { 01 23 45 67 [0-20] 77 54 32 10 [0-20] 02 23 45 67 [0-20] 76 54 32 10 }

  condition:
    $a0
}