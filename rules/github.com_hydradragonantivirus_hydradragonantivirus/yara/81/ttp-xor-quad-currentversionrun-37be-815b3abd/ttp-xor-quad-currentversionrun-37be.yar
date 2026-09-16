rule TTP_XOR_QUAD_CurrentVersionRun_37be {
  strings:
    $key_37be = { 64 d1 [2] 40 df [2] 6b f3 [2] 45 d1 [2] 51 ca [2] 5e d0 [2] 40 cd [2] 42 cc [2] 59 ca [2] 45 cd [2] 59 e2 }

  condition:
    any of them
}