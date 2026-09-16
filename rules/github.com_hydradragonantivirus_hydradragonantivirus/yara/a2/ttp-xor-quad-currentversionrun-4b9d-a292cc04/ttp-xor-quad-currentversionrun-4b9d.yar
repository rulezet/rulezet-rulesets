rule TTP_XOR_QUAD_CurrentVersionRun_4b9d {
  strings:
    $key_4b9d = { 18 f2 [2] 3c fc [2] 17 d0 [2] 39 f2 [2] 2d e9 [2] 22 f3 [2] 3c ee [2] 3e ef [2] 25 e9 [2] 39 ee [2] 25 c1 }

  condition:
    any of them
}