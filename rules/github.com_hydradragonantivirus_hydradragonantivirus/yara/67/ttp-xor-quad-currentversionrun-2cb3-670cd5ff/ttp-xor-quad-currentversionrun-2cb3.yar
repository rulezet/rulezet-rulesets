rule TTP_XOR_QUAD_CurrentVersionRun_2cb3 {
  strings:
    $key_2cb3 = { 7f dc [2] 5b d2 [2] 70 fe [2] 5e dc [2] 4a c7 [2] 45 dd [2] 5b c0 [2] 59 c1 [2] 42 c7 [2] 5e c0 [2] 42 ef }

  condition:
    any of them
}