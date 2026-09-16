rule TTP_XOR_QUAD_CurrentVersionRun_cbbf {
  strings:
    $key_cbbf = { 98 d0 [2] bc de [2] 97 f2 [2] b9 d0 [2] ad cb [2] a2 d1 [2] bc cc [2] be cd [2] a5 cb [2] b9 cc [2] a5 e3 }

  condition:
    any of them
}