rule TTP_XOR_QUAD_CurrentVersionRun_1b64 {
  strings:
    $key_1b64 = { 48 0b [2] 6c 05 [2] 47 29 [2] 69 0b [2] 7d 10 [2] 72 0a [2] 6c 17 [2] 6e 16 [2] 75 10 [2] 69 17 [2] 75 38 }

  condition:
    any of them
}