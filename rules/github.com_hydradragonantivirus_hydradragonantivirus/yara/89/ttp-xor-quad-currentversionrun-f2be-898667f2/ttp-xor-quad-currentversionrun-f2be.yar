rule TTP_XOR_QUAD_CurrentVersionRun_f2be {
  strings:
    $key_f2be = { a1 d1 [2] 85 df [2] ae f3 [2] 80 d1 [2] 94 ca [2] 9b d0 [2] 85 cd [2] 87 cc [2] 9c ca [2] 80 cd [2] 9c e2 }

  condition:
    any of them
}