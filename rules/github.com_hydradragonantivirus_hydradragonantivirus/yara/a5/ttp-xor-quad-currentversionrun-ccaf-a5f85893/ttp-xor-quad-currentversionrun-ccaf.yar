rule TTP_XOR_QUAD_CurrentVersionRun_ccaf {
  strings:
    $key_ccaf = { 9f c0 [2] bb ce [2] 90 e2 [2] be c0 [2] aa db [2] a5 c1 [2] bb dc [2] b9 dd [2] a2 db [2] be dc [2] a2 f3 }

  condition:
    any of them
}