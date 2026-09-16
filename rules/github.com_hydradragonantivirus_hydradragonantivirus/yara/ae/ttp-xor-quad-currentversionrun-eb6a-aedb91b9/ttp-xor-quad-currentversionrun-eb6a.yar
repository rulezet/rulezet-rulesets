rule TTP_XOR_QUAD_CurrentVersionRun_eb6a {
  strings:
    $key_eb6a = { b8 05 [2] 9c 0b [2] b7 27 [2] 99 05 [2] 8d 1e [2] 82 04 [2] 9c 19 [2] 9e 18 [2] 85 1e [2] 99 19 [2] 85 36 }

  condition:
    any of them
}