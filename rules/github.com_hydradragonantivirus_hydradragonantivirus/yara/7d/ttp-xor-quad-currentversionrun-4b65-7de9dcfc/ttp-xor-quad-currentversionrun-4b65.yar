rule TTP_XOR_QUAD_CurrentVersionRun_4b65 {
  strings:
    $key_4b65 = { 18 0a [2] 3c 04 [2] 17 28 [2] 39 0a [2] 2d 11 [2] 22 0b [2] 3c 16 [2] 3e 17 [2] 25 11 [2] 39 16 [2] 25 39 }

  condition:
    any of them
}