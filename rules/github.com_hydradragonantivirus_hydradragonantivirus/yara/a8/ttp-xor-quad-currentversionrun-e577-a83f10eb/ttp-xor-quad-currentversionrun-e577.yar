rule TTP_XOR_QUAD_CurrentVersionRun_e577 {
  strings:
    $key_e577 = { b6 18 [2] 92 16 [2] b9 3a [2] 97 18 [2] 83 03 [2] 8c 19 [2] 92 04 [2] 90 05 [2] 8b 03 [2] 97 04 [2] 8b 2b }

  condition:
    any of them
}