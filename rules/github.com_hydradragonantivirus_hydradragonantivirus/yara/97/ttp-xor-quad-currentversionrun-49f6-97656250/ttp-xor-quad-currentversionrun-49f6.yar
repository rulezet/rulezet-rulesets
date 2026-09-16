rule TTP_XOR_QUAD_CurrentVersionRun_49f6 {
  strings:
    $key_49f6 = { 1a 99 [2] 3e 97 [2] 15 bb [2] 3b 99 [2] 2f 82 [2] 20 98 [2] 3e 85 [2] 3c 84 [2] 27 82 [2] 3b 85 [2] 27 aa }

  condition:
    any of them
}