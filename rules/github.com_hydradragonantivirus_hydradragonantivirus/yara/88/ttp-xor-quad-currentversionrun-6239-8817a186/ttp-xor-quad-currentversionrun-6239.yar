rule TTP_XOR_QUAD_CurrentVersionRun_6239 {
  strings:
    $key_6239 = { 31 56 [2] 15 58 [2] 3e 74 [2] 10 56 [2] 04 4d [2] 0b 57 [2] 15 4a [2] 17 4b [2] 0c 4d [2] 10 4a [2] 0c 65 }

  condition:
    any of them
}