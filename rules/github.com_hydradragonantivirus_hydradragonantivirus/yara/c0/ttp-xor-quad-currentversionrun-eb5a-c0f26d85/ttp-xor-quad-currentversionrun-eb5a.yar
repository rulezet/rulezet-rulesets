rule TTP_XOR_QUAD_CurrentVersionRun_eb5a {
  strings:
    $key_eb5a = { b8 35 [2] 9c 3b [2] b7 17 [2] 99 35 [2] 8d 2e [2] 82 34 [2] 9c 29 [2] 9e 28 [2] 85 2e [2] 99 29 [2] 85 06 }

  condition:
    any of them
}