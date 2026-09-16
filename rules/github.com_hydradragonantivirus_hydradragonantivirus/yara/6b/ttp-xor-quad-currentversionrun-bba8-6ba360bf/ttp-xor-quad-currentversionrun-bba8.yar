rule TTP_XOR_QUAD_CurrentVersionRun_bba8 {
  strings:
    $key_bba8 = { e8 c7 [2] cc c9 [2] e7 e5 [2] c9 c7 [2] dd dc [2] d2 c6 [2] cc db [2] ce da [2] d5 dc [2] c9 db [2] d5 f4 }

  condition:
    any of them
}