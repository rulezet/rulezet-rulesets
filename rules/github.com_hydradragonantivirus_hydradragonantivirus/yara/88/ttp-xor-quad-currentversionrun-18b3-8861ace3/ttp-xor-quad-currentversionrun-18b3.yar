rule TTP_XOR_QUAD_CurrentVersionRun_18b3 {
  strings:
    $key_18b3 = { 4b dc [2] 6f d2 [2] 44 fe [2] 6a dc [2] 7e c7 [2] 71 dd [2] 6f c0 [2] 6d c1 [2] 76 c7 [2] 6a c0 [2] 76 ef }

  condition:
    any of them
}