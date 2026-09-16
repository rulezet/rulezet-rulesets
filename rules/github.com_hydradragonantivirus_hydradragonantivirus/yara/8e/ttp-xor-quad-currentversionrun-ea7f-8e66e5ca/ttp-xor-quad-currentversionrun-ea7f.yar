rule TTP_XOR_QUAD_CurrentVersionRun_ea7f {
  strings:
    $key_ea7f = { b9 10 [2] 9d 1e [2] b6 32 [2] 98 10 [2] 8c 0b [2] 83 11 [2] 9d 0c [2] 9f 0d [2] 84 0b [2] 98 0c [2] 84 23 }

  condition:
    any of them
}