rule TTP_XOR_QUAD_CurrentVersionRun_ea63 {
  strings:
    $key_ea63 = { b9 0c [2] 9d 02 [2] b6 2e [2] 98 0c [2] 8c 17 [2] 83 0d [2] 9d 10 [2] 9f 11 [2] 84 17 [2] 98 10 [2] 84 3f }

  condition:
    any of them
}