rule TTP_XOR_QUAD_CurrentVersionRun_aca9 {
  strings:
    $key_aca9 = { ff c6 [2] db c8 [2] f0 e4 [2] de c6 [2] ca dd [2] c5 c7 [2] db da [2] d9 db [2] c2 dd [2] de da [2] c2 f5 }

  condition:
    any of them
}