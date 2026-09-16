rule TTP_XOR_QUAD_CurrentVersionRun_6ef3 {
  strings:
    $key_6ef3 = { 3d 9c [2] 19 92 [2] 32 be [2] 1c 9c [2] 08 87 [2] 07 9d [2] 19 80 [2] 1b 81 [2] 00 87 [2] 1c 80 [2] 00 af }

  condition:
    any of them
}