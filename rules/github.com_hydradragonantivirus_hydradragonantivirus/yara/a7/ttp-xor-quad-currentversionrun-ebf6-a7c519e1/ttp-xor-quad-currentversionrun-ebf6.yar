rule TTP_XOR_QUAD_CurrentVersionRun_ebf6 {
  strings:
    $key_ebf6 = { b8 99 [2] 9c 97 [2] b7 bb [2] 99 99 [2] 8d 82 [2] 82 98 [2] 9c 85 [2] 9e 84 [2] 85 82 [2] 99 85 [2] 85 aa }

  condition:
    any of them
}