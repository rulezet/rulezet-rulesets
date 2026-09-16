rule TTP_XOR_QUAD_CurrentVersionRun_2fb3 {
  strings:
    $key_2fb3 = { 7c dc [2] 58 d2 [2] 73 fe [2] 5d dc [2] 49 c7 [2] 46 dd [2] 58 c0 [2] 5a c1 [2] 41 c7 [2] 5d c0 [2] 41 ef }

  condition:
    any of them
}