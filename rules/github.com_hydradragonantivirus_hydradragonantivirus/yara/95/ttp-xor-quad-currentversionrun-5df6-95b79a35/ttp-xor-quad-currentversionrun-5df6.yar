rule TTP_XOR_QUAD_CurrentVersionRun_5df6 {
  strings:
    $key_5df6 = { 0e 99 [2] 2a 97 [2] 01 bb [2] 2f 99 [2] 3b 82 [2] 34 98 [2] 2a 85 [2] 28 84 [2] 33 82 [2] 2f 85 [2] 33 aa }

  condition:
    any of them
}