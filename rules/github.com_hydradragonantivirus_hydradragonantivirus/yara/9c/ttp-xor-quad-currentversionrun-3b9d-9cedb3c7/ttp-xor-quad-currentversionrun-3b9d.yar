rule TTP_XOR_QUAD_CurrentVersionRun_3b9d {
  strings:
    $key_3b9d = { 68 f2 [2] 4c fc [2] 67 d0 [2] 49 f2 [2] 5d e9 [2] 52 f3 [2] 4c ee [2] 4e ef [2] 55 e9 [2] 49 ee [2] 55 c1 }

  condition:
    any of them
}