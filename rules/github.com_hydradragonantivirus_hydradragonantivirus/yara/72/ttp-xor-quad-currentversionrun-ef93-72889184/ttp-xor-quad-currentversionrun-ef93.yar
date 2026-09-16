rule TTP_XOR_QUAD_CurrentVersionRun_ef93 {
  strings:
    $key_ef93 = { bc fc [2] 98 f2 [2] b3 de [2] 9d fc [2] 89 e7 [2] 86 fd [2] 98 e0 [2] 9a e1 [2] 81 e7 [2] 9d e0 [2] 81 cf }

  condition:
    any of them
}