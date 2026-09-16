rule TTP_XOR_QUAD_CurrentVersionRun_6b65 {
  strings:
    $key_6b65 = { 38 0a [2] 1c 04 [2] 37 28 [2] 19 0a [2] 0d 11 [2] 02 0b [2] 1c 16 [2] 1e 17 [2] 05 11 [2] 19 16 [2] 05 39 }

  condition:
    any of them
}