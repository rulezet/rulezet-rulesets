rule TTP_XOR_QUAD_CurrentVersionRun_4fb3 {
  strings:
    $key_4fb3 = { 1c dc [2] 38 d2 [2] 13 fe [2] 3d dc [2] 29 c7 [2] 26 dd [2] 38 c0 [2] 3a c1 [2] 21 c7 [2] 3d c0 [2] 21 ef }

  condition:
    any of them
}