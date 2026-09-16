rule TTP_XOR_QUAD_CurrentVersionRun_b0af {
  strings:
    $key_b0af = { e3 c0 [2] c7 ce [2] ec e2 [2] c2 c0 [2] d6 db [2] d9 c1 [2] c7 dc [2] c5 dd [2] de db [2] c2 dc [2] de f3 }

  condition:
    any of them
}