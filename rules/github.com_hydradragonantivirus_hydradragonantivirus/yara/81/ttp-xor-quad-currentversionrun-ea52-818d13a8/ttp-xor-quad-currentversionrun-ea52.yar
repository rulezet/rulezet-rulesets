rule TTP_XOR_QUAD_CurrentVersionRun_ea52 {
  strings:
    $key_ea52 = { b9 3d [2] 9d 33 [2] b6 1f [2] 98 3d [2] 8c 26 [2] 83 3c [2] 9d 21 [2] 9f 20 [2] 84 26 [2] 98 21 [2] 84 0e }

  condition:
    any of them
}