rule TTP_XOR_QUAD_CurrentVersionRun_3fb3 {
  strings:
    $key_3fb3 = { 6c dc [2] 48 d2 [2] 63 fe [2] 4d dc [2] 59 c7 [2] 56 dd [2] 48 c0 [2] 4a c1 [2] 51 c7 [2] 4d c0 [2] 51 ef }

  condition:
    any of them
}