rule TTP_XOR_QUAD_CurrentVersionRun_ea3a {
  strings:
    $key_ea3a = { b9 55 [2] 9d 5b [2] b6 77 [2] 98 55 [2] 8c 4e [2] 83 54 [2] 9d 49 [2] 9f 48 [2] 84 4e [2] 98 49 [2] 84 66 }

  condition:
    any of them
}