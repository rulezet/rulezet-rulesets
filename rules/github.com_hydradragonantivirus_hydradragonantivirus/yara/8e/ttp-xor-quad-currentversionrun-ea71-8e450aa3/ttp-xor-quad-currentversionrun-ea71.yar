rule TTP_XOR_QUAD_CurrentVersionRun_ea71 {
  strings:
    $key_ea71 = { b9 1e [2] 9d 10 [2] b6 3c [2] 98 1e [2] 8c 05 [2] 83 1f [2] 9d 02 [2] 9f 03 [2] 84 05 [2] 98 02 [2] 84 2d }

  condition:
    any of them
}