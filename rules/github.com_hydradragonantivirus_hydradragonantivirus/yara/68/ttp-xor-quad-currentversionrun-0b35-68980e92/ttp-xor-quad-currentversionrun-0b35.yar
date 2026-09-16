rule TTP_XOR_QUAD_CurrentVersionRun_0b35 {
  strings:
    $key_0b35 = { 58 5a [2] 7c 54 [2] 57 78 [2] 79 5a [2] 6d 41 [2] 62 5b [2] 7c 46 [2] 7e 47 [2] 65 41 [2] 79 46 [2] 65 69 }

  condition:
    any of them
}