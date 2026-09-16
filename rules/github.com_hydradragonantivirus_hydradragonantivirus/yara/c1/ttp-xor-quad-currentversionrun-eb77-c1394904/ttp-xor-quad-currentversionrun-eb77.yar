rule TTP_XOR_QUAD_CurrentVersionRun_eb77 {
  strings:
    $key_eb77 = { b8 18 [2] 9c 16 [2] b7 3a [2] 99 18 [2] 8d 03 [2] 82 19 [2] 9c 04 [2] 9e 05 [2] 85 03 [2] 99 04 [2] 85 2b }

  condition:
    any of them
}