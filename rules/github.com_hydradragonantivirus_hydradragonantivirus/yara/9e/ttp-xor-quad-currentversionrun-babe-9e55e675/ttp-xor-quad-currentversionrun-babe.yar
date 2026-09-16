rule TTP_XOR_QUAD_CurrentVersionRun_babe {
  strings:
    $key_babe = { e9 d1 [2] cd df [2] e6 f3 [2] c8 d1 [2] dc ca [2] d3 d0 [2] cd cd [2] cf cc [2] d4 ca [2] c8 cd [2] d4 e2 }

  condition:
    any of them
}