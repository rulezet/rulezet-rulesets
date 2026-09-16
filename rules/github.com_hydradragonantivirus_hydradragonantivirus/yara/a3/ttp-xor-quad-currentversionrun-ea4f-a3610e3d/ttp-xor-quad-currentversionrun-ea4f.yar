rule TTP_XOR_QUAD_CurrentVersionRun_ea4f {
  strings:
    $key_ea4f = { b9 20 [2] 9d 2e [2] b6 02 [2] 98 20 [2] 8c 3b [2] 83 21 [2] 9d 3c [2] 9f 3d [2] 84 3b [2] 98 3c [2] 84 13 }

  condition:
    any of them
}