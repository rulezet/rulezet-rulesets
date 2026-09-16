rule TTP_XOR_QUAD_CurrentVersionRun_e3be {
  strings:
    $key_e3be = { b0 d1 [2] 94 df [2] bf f3 [2] 91 d1 [2] 85 ca [2] 8a d0 [2] 94 cd [2] 96 cc [2] 8d ca [2] 91 cd [2] 8d e2 }

  condition:
    any of them
}