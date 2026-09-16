rule TTP_XOR_QUAD_CurrentVersionRun_ecb3 {
  strings:
    $key_ecb3 = { bf dc [2] 9b d2 [2] b0 fe [2] 9e dc [2] 8a c7 [2] 85 dd [2] 9b c0 [2] 99 c1 [2] 82 c7 [2] 9e c0 [2] 82 ef }

  condition:
    any of them
}