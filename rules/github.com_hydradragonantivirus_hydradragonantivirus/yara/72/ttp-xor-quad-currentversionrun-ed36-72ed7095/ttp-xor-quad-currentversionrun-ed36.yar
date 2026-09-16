rule TTP_XOR_QUAD_CurrentVersionRun_ed36 {
  strings:
    $key_ed36 = { be 59 [2] 9a 57 [2] b1 7b [2] 9f 59 [2] 8b 42 [2] 84 58 [2] 9a 45 [2] 98 44 [2] 83 42 [2] 9f 45 [2] 83 6a }

  condition:
    any of them
}