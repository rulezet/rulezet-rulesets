rule TTP_XOR_QUAD_CurrentVersionRun_dba6 {
  strings:
    $key_dba6 = { 88 c9 [2] ac c7 [2] 87 eb [2] a9 c9 [2] bd d2 [2] b2 c8 [2] ac d5 [2] ae d4 [2] b5 d2 [2] a9 d5 [2] b5 fa }

  condition:
    any of them
}