rule TTP_XOR_QUAD_CurrentVersionRun_e247 {
  strings:
    $key_e247 = { b1 28 [2] 95 26 [2] be 0a [2] 90 28 [2] 84 33 [2] 8b 29 [2] 95 34 [2] 97 35 [2] 8c 33 [2] 90 34 [2] 8c 1b }

  condition:
    any of them
}