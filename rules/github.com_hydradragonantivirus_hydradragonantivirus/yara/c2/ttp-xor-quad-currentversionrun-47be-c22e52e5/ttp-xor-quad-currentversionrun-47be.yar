rule TTP_XOR_QUAD_CurrentVersionRun_47be {
  strings:
    $key_47be = { 14 d1 [2] 30 df [2] 1b f3 [2] 35 d1 [2] 21 ca [2] 2e d0 [2] 30 cd [2] 32 cc [2] 29 ca [2] 35 cd [2] 29 e2 }

  condition:
    any of them
}