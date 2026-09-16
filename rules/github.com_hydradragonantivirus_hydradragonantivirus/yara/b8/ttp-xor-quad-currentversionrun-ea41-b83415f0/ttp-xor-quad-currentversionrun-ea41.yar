rule TTP_XOR_QUAD_CurrentVersionRun_ea41 {
  strings:
    $key_ea41 = { b9 2e [2] 9d 20 [2] b6 0c [2] 98 2e [2] 8c 35 [2] 83 2f [2] 9d 32 [2] 9f 33 [2] 84 35 [2] 98 32 [2] 84 1d }

  condition:
    any of them
}