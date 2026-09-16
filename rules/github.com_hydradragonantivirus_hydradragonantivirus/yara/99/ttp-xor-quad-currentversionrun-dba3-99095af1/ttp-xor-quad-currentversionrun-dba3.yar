rule TTP_XOR_QUAD_CurrentVersionRun_dba3 {
  strings:
    $key_dba3 = { 88 cc [2] ac c2 [2] 87 ee [2] a9 cc [2] bd d7 [2] b2 cd [2] ac d0 [2] ae d1 [2] b5 d7 [2] a9 d0 [2] b5 ff }

  condition:
    any of them
}