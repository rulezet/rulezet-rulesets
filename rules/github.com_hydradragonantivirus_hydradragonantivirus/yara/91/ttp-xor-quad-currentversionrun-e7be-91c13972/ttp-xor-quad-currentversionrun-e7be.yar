rule TTP_XOR_QUAD_CurrentVersionRun_e7be {
  strings:
    $key_e7be = { b4 d1 [2] 90 df [2] bb f3 [2] 95 d1 [2] 81 ca [2] 8e d0 [2] 90 cd [2] 92 cc [2] 89 ca [2] 95 cd [2] 89 e2 }

  condition:
    any of them
}