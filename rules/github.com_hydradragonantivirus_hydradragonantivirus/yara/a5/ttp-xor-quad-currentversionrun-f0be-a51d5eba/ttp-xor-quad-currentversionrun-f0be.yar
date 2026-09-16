rule TTP_XOR_QUAD_CurrentVersionRun_f0be {
  strings:
    $key_f0be = { a3 d1 [2] 87 df [2] ac f3 [2] 82 d1 [2] 96 ca [2] 99 d0 [2] 87 cd [2] 85 cc [2] 9e ca [2] 82 cd [2] 9e e2 }

  condition:
    any of them
}