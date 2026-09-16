rule TTP_XOR_QUAD_CurrentVersionRun_0b34 {
  strings:
    $key_0b34 = { 58 5b [2] 7c 55 [2] 57 79 [2] 79 5b [2] 6d 40 [2] 62 5a [2] 7c 47 [2] 7e 46 [2] 65 40 [2] 79 47 [2] 65 68 }

  condition:
    any of them
}