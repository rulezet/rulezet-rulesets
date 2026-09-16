rule TTP_XOR_QUAD_CurrentVersionRun_bbdd {
  strings:
    $key_bbdd = { e8 b2 [2] cc bc [2] e7 90 [2] c9 b2 [2] dd a9 [2] d2 b3 [2] cc ae [2] ce af [2] d5 a9 [2] c9 ae [2] d5 81 }

  condition:
    any of them
}