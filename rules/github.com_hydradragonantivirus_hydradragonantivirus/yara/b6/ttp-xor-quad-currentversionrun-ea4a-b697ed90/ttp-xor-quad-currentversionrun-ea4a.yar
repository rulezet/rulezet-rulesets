rule TTP_XOR_QUAD_CurrentVersionRun_ea4a {
  strings:
    $key_ea4a = { b9 25 [2] 9d 2b [2] b6 07 [2] 98 25 [2] 8c 3e [2] 83 24 [2] 9d 39 [2] 9f 38 [2] 84 3e [2] 98 39 [2] 84 16 }

  condition:
    any of them
}