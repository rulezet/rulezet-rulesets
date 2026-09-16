rule TTP_XOR_QUAD_CurrentVersionRun_dba8 {
  strings:
    $key_dba8 = { 88 c7 [2] ac c9 [2] 87 e5 [2] a9 c7 [2] bd dc [2] b2 c6 [2] ac db [2] ae da [2] b5 dc [2] a9 db [2] b5 f4 }

  condition:
    any of them
}