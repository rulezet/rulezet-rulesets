rule TTP_XOR_QUAD_CurrentVersionRun_ccae {
  strings:
    $key_ccae = { 9f c1 [2] bb cf [2] 90 e3 [2] be c1 [2] aa da [2] a5 c0 [2] bb dd [2] b9 dc [2] a2 da [2] be dd [2] a2 f2 }

  condition:
    any of them
}