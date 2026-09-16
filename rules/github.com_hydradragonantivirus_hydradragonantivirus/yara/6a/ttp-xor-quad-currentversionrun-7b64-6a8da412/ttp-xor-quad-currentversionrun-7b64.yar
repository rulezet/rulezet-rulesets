rule TTP_XOR_QUAD_CurrentVersionRun_7b64 {
  strings:
    $key_7b64 = { 28 0b [2] 0c 05 [2] 27 29 [2] 09 0b [2] 1d 10 [2] 12 0a [2] 0c 17 [2] 0e 16 [2] 15 10 [2] 09 17 [2] 15 38 }

  condition:
    any of them
}