rule TTP_XOR_QUAD_CurrentVersionRun_e2be {
  strings:
    $key_e2be = { b1 d1 [2] 95 df [2] be f3 [2] 90 d1 [2] 84 ca [2] 8b d0 [2] 95 cd [2] 97 cc [2] 8c ca [2] 90 cd [2] 8c e2 }

  condition:
    any of them
}