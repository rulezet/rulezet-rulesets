rule TTP_XOR_QUAD_CurrentVersionRun_c9be {
  strings:
    $key_c9be = { 9a d1 [2] be df [2] 95 f3 [2] bb d1 [2] af ca [2] a0 d0 [2] be cd [2] bc cc [2] a7 ca [2] bb cd [2] a7 e2 }

  condition:
    any of them
}