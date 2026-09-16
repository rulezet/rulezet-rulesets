rule TTP_XOR_QUAD_CurrentVersionRun_eb62 {
  strings:
    $key_eb62 = { b8 0d [2] 9c 03 [2] b7 2f [2] 99 0d [2] 8d 16 [2] 82 0c [2] 9c 11 [2] 9e 10 [2] 85 16 [2] 99 11 [2] 85 3e }

  condition:
    any of them
}