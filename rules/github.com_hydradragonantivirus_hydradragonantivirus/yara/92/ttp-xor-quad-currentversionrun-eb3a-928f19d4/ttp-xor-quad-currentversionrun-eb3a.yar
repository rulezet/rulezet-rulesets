rule TTP_XOR_QUAD_CurrentVersionRun_eb3a {
  strings:
    $key_eb3a = { b8 55 [2] 9c 5b [2] b7 77 [2] 99 55 [2] 8d 4e [2] 82 54 [2] 9c 49 [2] 9e 48 [2] 85 4e [2] 99 49 [2] 85 66 }

  condition:
    any of them
}