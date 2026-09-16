rule TTP_XOR_QUAD_CurrentVersionRun_ea13 {
  strings:
    $key_ea13 = { b9 7c [2] 9d 72 [2] b6 5e [2] 98 7c [2] 8c 67 [2] 83 7d [2] 9d 60 [2] 9f 61 [2] 84 67 [2] 98 60 [2] 84 4f }

  condition:
    any of them
}