rule TTP_XOR_QUAD_CurrentVersionRun_1b9d {
  strings:
    $key_1b9d = { 48 f2 [2] 6c fc [2] 47 d0 [2] 69 f2 [2] 7d e9 [2] 72 f3 [2] 6c ee [2] 6e ef [2] 75 e9 [2] 69 ee [2] 75 c1 }

  condition:
    any of them
}