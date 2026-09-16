rule TTP_XOR_QUAD_CurrentVersionRun_6b64 {
  strings:
    $key_6b64 = { 38 0b [2] 1c 05 [2] 37 29 [2] 19 0b [2] 0d 10 [2] 02 0a [2] 1c 17 [2] 1e 16 [2] 05 10 [2] 19 17 [2] 05 38 }

  condition:
    any of them
}