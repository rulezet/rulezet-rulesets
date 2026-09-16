rule TTP_XOR_QUAD_CurrentVersionRun_eb02 {
  strings:
    $key_eb02 = { b8 6d [2] 9c 63 [2] b7 4f [2] 99 6d [2] 8d 76 [2] 82 6c [2] 9c 71 [2] 9e 70 [2] 85 76 [2] 99 71 [2] 85 5e }

  condition:
    any of them
}