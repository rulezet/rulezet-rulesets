rule TTP_XOR_QUAD_CurrentVersionRun_6d35 {
  strings:
    $key_6d35 = { 3e 5a [2] 1a 54 [2] 31 78 [2] 1f 5a [2] 0b 41 [2] 04 5b [2] 1a 46 [2] 18 47 [2] 03 41 [2] 1f 46 [2] 03 69 }

  condition:
    any of them
}