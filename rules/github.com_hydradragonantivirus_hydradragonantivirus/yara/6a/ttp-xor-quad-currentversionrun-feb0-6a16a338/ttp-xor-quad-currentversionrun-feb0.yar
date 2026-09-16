rule TTP_XOR_QUAD_CurrentVersionRun_feb0 {
  strings:
    $key_feb0 = { ad df [2] 89 d1 [2] a2 fd [2] 8c df [2] 98 c4 [2] 97 de [2] 89 c3 [2] 8b c2 [2] 90 c4 [2] 8c c3 [2] 90 ec }

  condition:
    any of them
}