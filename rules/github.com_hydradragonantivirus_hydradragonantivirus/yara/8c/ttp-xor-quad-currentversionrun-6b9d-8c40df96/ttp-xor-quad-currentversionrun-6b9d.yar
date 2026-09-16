rule TTP_XOR_QUAD_CurrentVersionRun_6b9d {
  strings:
    $key_6b9d = { 38 f2 [2] 1c fc [2] 37 d0 [2] 19 f2 [2] 0d e9 [2] 02 f3 [2] 1c ee [2] 1e ef [2] 05 e9 [2] 19 ee [2] 05 c1 }

  condition:
    any of them
}