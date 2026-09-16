rule TTP_XOR_QUAD_CurrentVersionRun_5493 {
  strings:
    $key_5493 = { 07 fc [2] 23 f2 [2] 08 de [2] 26 fc [2] 32 e7 [2] 3d fd [2] 23 e0 [2] 21 e1 [2] 3a e7 [2] 26 e0 [2] 3a cf }

  condition:
    any of them
}