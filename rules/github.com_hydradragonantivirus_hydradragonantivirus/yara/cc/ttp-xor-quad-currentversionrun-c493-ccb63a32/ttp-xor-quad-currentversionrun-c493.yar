rule TTP_XOR_QUAD_CurrentVersionRun_c493 {
  strings:
    $key_c493 = { 97 fc [2] b3 f2 [2] 98 de [2] b6 fc [2] a2 e7 [2] ad fd [2] b3 e0 [2] b1 e1 [2] aa e7 [2] b6 e0 [2] aa cf }

  condition:
    any of them
}