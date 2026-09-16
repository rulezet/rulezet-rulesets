rule TTP_XOR_QUAD_CurrentVersionRun_ea2f {
  strings:
    $key_ea2f = { b9 40 [2] 9d 4e [2] b6 62 [2] 98 40 [2] 8c 5b [2] 83 41 [2] 9d 5c [2] 9f 5d [2] 84 5b [2] 98 5c [2] 84 73 }

  condition:
    any of them
}