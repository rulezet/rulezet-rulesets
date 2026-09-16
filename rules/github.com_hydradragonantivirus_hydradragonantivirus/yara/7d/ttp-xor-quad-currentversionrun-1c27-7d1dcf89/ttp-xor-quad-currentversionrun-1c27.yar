rule TTP_XOR_QUAD_CurrentVersionRun_1c27 {
  strings:
    $key_1c27 = { 4f 48 [2] 6b 46 [2] 40 6a [2] 6e 48 [2] 7a 53 [2] 75 49 [2] 6b 54 [2] 69 55 [2] 72 53 [2] 6e 54 [2] 72 7b }

  condition:
    any of them
}