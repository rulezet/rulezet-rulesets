rule TTP_XOR_QUAD_CurrentVersionRun_ebf7 {
  strings:
    $key_ebf7 = { b8 98 [2] 9c 96 [2] b7 ba [2] 99 98 [2] 8d 83 [2] 82 99 [2] 9c 84 [2] 9e 85 [2] 85 83 [2] 99 84 [2] 85 ab }

  condition:
    any of them
}