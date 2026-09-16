rule TTP_XOR_QUAD_CurrentVersionRun_0b28 {
  strings:
    $key_0b28 = { 58 47 [2] 7c 49 [2] 57 65 [2] 79 47 [2] 6d 5c [2] 62 46 [2] 7c 5b [2] 7e 5a [2] 65 5c [2] 79 5b [2] 65 74 }

  condition:
    any of them
}