rule TTP_XOR_QUAD_CurrentVersionRun_0c27 {
  strings:
    $key_0c27 = { 5f 48 [2] 7b 46 [2] 50 6a [2] 7e 48 [2] 6a 53 [2] 65 49 [2] 7b 54 [2] 79 55 [2] 62 53 [2] 7e 54 [2] 62 7b }

  condition:
    any of them
}