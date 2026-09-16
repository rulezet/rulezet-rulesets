rule TTP_XOR_QUAD_CurrentVersionRun_ea3f {
  strings:
    $key_ea3f = { b9 50 [2] 9d 5e [2] b6 72 [2] 98 50 [2] 8c 4b [2] 83 51 [2] 9d 4c [2] 9f 4d [2] 84 4b [2] 98 4c [2] 84 63 }

  condition:
    any of them
}