rule TTP_XOR_QUAD_CurrentVersionRun_ea01 {
  strings:
    $key_ea01 = { b9 6e [2] 9d 60 [2] b6 4c [2] 98 6e [2] 8c 75 [2] 83 6f [2] 9d 72 [2] 9f 73 [2] 84 75 [2] 98 72 [2] 84 5d }

  condition:
    any of them
}