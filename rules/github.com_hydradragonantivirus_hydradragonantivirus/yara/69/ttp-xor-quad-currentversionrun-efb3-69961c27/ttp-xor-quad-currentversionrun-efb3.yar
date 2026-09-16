rule TTP_XOR_QUAD_CurrentVersionRun_efb3 {
  strings:
    $key_efb3 = { bc dc [2] 98 d2 [2] b3 fe [2] 9d dc [2] 89 c7 [2] 86 dd [2] 98 c0 [2] 9a c1 [2] 81 c7 [2] 9d c0 [2] 81 ef }

  condition:
    any of them
}