rule TTP_XOR_QUAD_CurrentVersionRun_0df3 {
  strings:
    $key_0df3 = { 5e 9c [2] 7a 92 [2] 51 be [2] 7f 9c [2] 6b 87 [2] 64 9d [2] 7a 80 [2] 78 81 [2] 63 87 [2] 7f 80 [2] 63 af }

  condition:
    any of them
}