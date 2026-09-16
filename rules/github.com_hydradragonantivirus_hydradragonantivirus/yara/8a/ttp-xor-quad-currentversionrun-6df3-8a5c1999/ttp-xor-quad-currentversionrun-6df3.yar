rule TTP_XOR_QUAD_CurrentVersionRun_6df3 {
  strings:
    $key_6df3 = { 3e 9c [2] 1a 92 [2] 31 be [2] 1f 9c [2] 0b 87 [2] 04 9d [2] 1a 80 [2] 18 81 [2] 03 87 [2] 1f 80 [2] 03 af }

  condition:
    any of them
}