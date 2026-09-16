rule TTP_XOR_QUAD_CurrentVersionRun_e9be {
  strings:
    $key_e9be = { ba d1 [2] 9e df [2] b5 f3 [2] 9b d1 [2] 8f ca [2] 80 d0 [2] 9e cd [2] 9c cc [2] 87 ca [2] 9b cd [2] 87 e2 }

  condition:
    any of them
}