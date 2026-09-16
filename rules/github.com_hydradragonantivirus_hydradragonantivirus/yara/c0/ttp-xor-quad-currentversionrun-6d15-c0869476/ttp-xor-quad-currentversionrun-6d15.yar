rule TTP_XOR_QUAD_CurrentVersionRun_6d15 {
  strings:
    $key_6d15 = { 3e 7a [2] 1a 74 [2] 31 58 [2] 1f 7a [2] 0b 61 [2] 04 7b [2] 1a 66 [2] 18 67 [2] 03 61 [2] 1f 66 [2] 03 49 }

  condition:
    any of them
}