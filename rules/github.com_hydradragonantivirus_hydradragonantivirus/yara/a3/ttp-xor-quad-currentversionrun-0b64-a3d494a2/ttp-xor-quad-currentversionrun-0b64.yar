rule TTP_XOR_QUAD_CurrentVersionRun_0b64 {
  strings:
    $key_0b64 = { 58 0b [2] 7c 05 [2] 57 29 [2] 79 0b [2] 6d 10 [2] 62 0a [2] 7c 17 [2] 7e 16 [2] 65 10 [2] 79 17 [2] 65 38 }

  condition:
    any of them
}