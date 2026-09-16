rule TTP_XOR_QUAD_CurrentVersionRun_2517 {
  strings:
    $key_2517 = { 76 78 [2] 52 76 [2] 79 5a [2] 57 78 [2] 43 63 [2] 4c 79 [2] 52 64 [2] 50 65 [2] 4b 63 [2] 57 64 [2] 4b 4b }

  condition:
    any of them
}