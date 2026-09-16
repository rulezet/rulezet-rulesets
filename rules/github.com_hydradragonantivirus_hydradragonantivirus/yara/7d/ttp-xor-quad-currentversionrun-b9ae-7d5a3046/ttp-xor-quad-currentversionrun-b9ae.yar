rule TTP_XOR_QUAD_CurrentVersionRun_b9ae {
  strings:
    $key_b9ae = { ea c1 [2] ce cf [2] e5 e3 [2] cb c1 [2] df da [2] d0 c0 [2] ce dd [2] cc dc [2] d7 da [2] cb dd [2] d7 f2 }

  condition:
    any of them
}