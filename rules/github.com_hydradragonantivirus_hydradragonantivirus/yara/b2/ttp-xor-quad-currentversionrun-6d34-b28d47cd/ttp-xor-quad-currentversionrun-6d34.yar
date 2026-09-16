rule TTP_XOR_QUAD_CurrentVersionRun_6d34 {
  strings:
    $key_6d34 = { 3e 5b [2] 1a 55 [2] 31 79 [2] 1f 5b [2] 0b 40 [2] 04 5a [2] 1a 47 [2] 18 46 [2] 03 40 [2] 1f 47 [2] 03 68 }

  condition:
    any of them
}