rule TTP_XOR_QUAD_CurrentVersionRun_eb72 {
  strings:
    $key_eb72 = { b8 1d [2] 9c 13 [2] b7 3f [2] 99 1d [2] 8d 06 [2] 82 1c [2] 9c 01 [2] 9e 00 [2] 85 06 [2] 99 01 [2] 85 2e }

  condition:
    any of them
}