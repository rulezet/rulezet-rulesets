rule TTP_XOR_QUAD_CurrentVersionRun_ea1e {
  strings:
    $key_ea1e = { b9 71 [2] 9d 7f [2] b6 53 [2] 98 71 [2] 8c 6a [2] 83 70 [2] 9d 6d [2] 9f 6c [2] 84 6a [2] 98 6d [2] 84 42 }

  condition:
    any of them
}