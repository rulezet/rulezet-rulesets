rule TTP_XOR_QUAD_CurrentVersionRun_0f27 {
  strings:
    $key_0f27 = { 5c 48 [2] 78 46 [2] 53 6a [2] 7d 48 [2] 69 53 [2] 66 49 [2] 78 54 [2] 7a 55 [2] 61 53 [2] 7d 54 [2] 61 7b }

  condition:
    any of them
}