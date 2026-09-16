rule TTP_XOR_QUAD_CurrentVersionRun_6cb3 {
  strings:
    $key_6cb3 = { 3f dc [2] 1b d2 [2] 30 fe [2] 1e dc [2] 0a c7 [2] 05 dd [2] 1b c0 [2] 19 c1 [2] 02 c7 [2] 1e c0 [2] 02 ef }

  condition:
    any of them
}