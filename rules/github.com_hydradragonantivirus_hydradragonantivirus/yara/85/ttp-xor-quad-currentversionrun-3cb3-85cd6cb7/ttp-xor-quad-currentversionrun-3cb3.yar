rule TTP_XOR_QUAD_CurrentVersionRun_3cb3 {
  strings:
    $key_3cb3 = { 6f dc [2] 4b d2 [2] 60 fe [2] 4e dc [2] 5a c7 [2] 55 dd [2] 4b c0 [2] 49 c1 [2] 52 c7 [2] 4e c0 [2] 52 ef }

  condition:
    any of them
}