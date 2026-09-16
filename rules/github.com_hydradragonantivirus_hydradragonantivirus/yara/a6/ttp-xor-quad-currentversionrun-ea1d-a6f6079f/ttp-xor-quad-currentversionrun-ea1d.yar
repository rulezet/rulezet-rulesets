rule TTP_XOR_QUAD_CurrentVersionRun_ea1d {
  strings:
    $key_ea1d = { b9 72 [2] 9d 7c [2] b6 50 [2] 98 72 [2] 8c 69 [2] 83 73 [2] 9d 6e [2] 9f 6f [2] 84 69 [2] 98 6e [2] 84 41 }

  condition:
    any of them
}