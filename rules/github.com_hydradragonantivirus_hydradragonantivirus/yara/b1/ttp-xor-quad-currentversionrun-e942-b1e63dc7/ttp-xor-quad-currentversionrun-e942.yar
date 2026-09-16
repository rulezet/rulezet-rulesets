rule TTP_XOR_QUAD_CurrentVersionRun_e942 {
  strings:
    $key_e942 = { ba 2d [2] 9e 23 [2] b5 0f [2] 9b 2d [2] 8f 36 [2] 80 2c [2] 9e 31 [2] 9c 30 [2] 87 36 [2] 9b 31 [2] 87 1e }

  condition:
    any of them
}