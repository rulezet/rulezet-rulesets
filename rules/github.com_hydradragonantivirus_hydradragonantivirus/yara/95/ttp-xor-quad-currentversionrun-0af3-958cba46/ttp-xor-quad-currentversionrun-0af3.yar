rule TTP_XOR_QUAD_CurrentVersionRun_0af3 {
  strings:
    $key_0af3 = { 59 9c [2] 7d 92 [2] 56 be [2] 78 9c [2] 6c 87 [2] 63 9d [2] 7d 80 [2] 7f 81 [2] 64 87 [2] 78 80 [2] 64 af }

  condition:
    any of them
}