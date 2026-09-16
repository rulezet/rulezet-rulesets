rule TTP_XOR_QUAD_CurrentVersionRun_d0be {
  strings:
    $key_d0be = { 83 d1 [2] a7 df [2] 8c f3 [2] a2 d1 [2] b6 ca [2] b9 d0 [2] a7 cd [2] a5 cc [2] be ca [2] a2 cd [2] be e2 }

  condition:
    any of them
}