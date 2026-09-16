rule TTP_XOR_QUAD_CurrentVersionRun_d393 {
  strings:
    $key_d393 = { 80 fc [2] a4 f2 [2] 8f de [2] a1 fc [2] b5 e7 [2] ba fd [2] a4 e0 [2] a6 e1 [2] bd e7 [2] a1 e0 [2] bd cf }

  condition:
    any of them
}