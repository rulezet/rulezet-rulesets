rule TTP_XOR_QUAD_CurrentVersionRun_ea1f {
  strings:
    $key_ea1f = { b9 70 [2] 9d 7e [2] b6 52 [2] 98 70 [2] 8c 6b [2] 83 71 [2] 9d 6c [2] 9f 6d [2] 84 6b [2] 98 6c [2] 84 43 }

  condition:
    any of them
}