rule TTP_XOR_QUAD_CurrentVersionRun_f3be {
  strings:
    $key_f3be = { a0 d1 [2] 84 df [2] af f3 [2] 81 d1 [2] 95 ca [2] 9a d0 [2] 84 cd [2] 86 cc [2] 9d ca [2] 81 cd [2] 9d e2 }

  condition:
    any of them
}