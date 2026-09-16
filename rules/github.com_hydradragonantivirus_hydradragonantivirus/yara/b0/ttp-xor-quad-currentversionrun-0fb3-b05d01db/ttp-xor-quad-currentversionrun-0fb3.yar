rule TTP_XOR_QUAD_CurrentVersionRun_0fb3 {
  strings:
    $key_0fb3 = { 5c dc [2] 78 d2 [2] 53 fe [2] 7d dc [2] 69 c7 [2] 66 dd [2] 78 c0 [2] 7a c1 [2] 61 c7 [2] 7d c0 [2] 61 ef }

  condition:
    any of them
}