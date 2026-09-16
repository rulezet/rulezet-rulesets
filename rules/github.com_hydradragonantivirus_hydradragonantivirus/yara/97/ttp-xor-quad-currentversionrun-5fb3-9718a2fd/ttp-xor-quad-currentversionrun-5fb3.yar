rule TTP_XOR_QUAD_CurrentVersionRun_5fb3 {
  strings:
    $key_5fb3 = { 0c dc [2] 28 d2 [2] 03 fe [2] 2d dc [2] 39 c7 [2] 36 dd [2] 28 c0 [2] 2a c1 [2] 31 c7 [2] 2d c0 [2] 31 ef }

  condition:
    any of them
}