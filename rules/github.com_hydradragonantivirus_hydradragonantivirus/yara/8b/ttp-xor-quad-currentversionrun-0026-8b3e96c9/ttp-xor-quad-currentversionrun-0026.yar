rule TTP_XOR_QUAD_CurrentVersionRun_0026 {
  strings:
    $key_0026 = { 53 49 [2] 77 47 [2] 5c 6b [2] 72 49 [2] 66 52 [2] 69 48 [2] 77 55 [2] 75 54 [2] 6e 52 [2] 72 55 [2] 6e 7a }

  condition:
    any of them
}