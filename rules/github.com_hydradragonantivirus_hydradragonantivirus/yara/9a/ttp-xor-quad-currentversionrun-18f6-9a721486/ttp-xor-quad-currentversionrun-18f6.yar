rule TTP_XOR_QUAD_CurrentVersionRun_18f6 {
  strings:
    $key_18f6 = { 4b 99 [2] 6f 97 [2] 44 bb [2] 6a 99 [2] 7e 82 [2] 71 98 [2] 6f 85 [2] 6d 84 [2] 76 82 [2] 6a 85 [2] 76 aa }

  condition:
    any of them
}