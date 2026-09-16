rule TTP_XOR_QUAD_CurrentVersionRun_2b9d {
  strings:
    $key_2b9d = { 78 f2 [2] 5c fc [2] 77 d0 [2] 59 f2 [2] 4d e9 [2] 42 f3 [2] 5c ee [2] 5e ef [2] 45 e9 [2] 59 ee [2] 45 c1 }

  condition:
    any of them
}