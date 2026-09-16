rule TTP_XOR_QUAD_CurrentVersionRun_e9f6 {
  strings:
    $key_e9f6 = { ba 99 [2] 9e 97 [2] b5 bb [2] 9b 99 [2] 8f 82 [2] 80 98 [2] 9e 85 [2] 9c 84 [2] 87 82 [2] 9b 85 [2] 87 aa }

  condition:
    any of them
}