rule TTP_XOR_QUAD_CurrentVersionRun_0b9d {
  strings:
    $key_0b9d = { 58 f2 [2] 7c fc [2] 57 d0 [2] 79 f2 [2] 6d e9 [2] 62 f3 [2] 7c ee [2] 7e ef [2] 65 e9 [2] 79 ee [2] 65 c1 }

  condition:
    any of them
}