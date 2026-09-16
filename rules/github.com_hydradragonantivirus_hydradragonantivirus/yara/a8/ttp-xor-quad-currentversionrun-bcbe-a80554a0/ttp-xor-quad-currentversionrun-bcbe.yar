rule TTP_XOR_QUAD_CurrentVersionRun_bcbe {
  strings:
    $key_bcbe = { ef d1 [2] cb df [2] e0 f3 [2] ce d1 [2] da ca [2] d5 d0 [2] cb cd [2] c9 cc [2] d2 ca [2] ce cd [2] d2 e2 }

  condition:
    any of them
}