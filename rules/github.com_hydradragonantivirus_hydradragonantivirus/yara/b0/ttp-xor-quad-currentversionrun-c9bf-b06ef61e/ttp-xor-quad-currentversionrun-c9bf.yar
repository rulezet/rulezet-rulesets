rule TTP_XOR_QUAD_CurrentVersionRun_c9bf {
  strings:
    $key_c9bf = { 9a d0 [2] be de [2] 95 f2 [2] bb d0 [2] af cb [2] a0 d1 [2] be cc [2] bc cd [2] a7 cb [2] bb cc [2] a7 e3 }

  condition:
    any of them
}