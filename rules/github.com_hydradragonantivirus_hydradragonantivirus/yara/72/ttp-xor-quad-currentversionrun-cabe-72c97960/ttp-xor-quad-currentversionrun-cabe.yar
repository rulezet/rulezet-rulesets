rule TTP_XOR_QUAD_CurrentVersionRun_cabe {
  strings:
    $key_cabe = { 99 d1 [2] bd df [2] 96 f3 [2] b8 d1 [2] ac ca [2] a3 d0 [2] bd cd [2] bf cc [2] a4 ca [2] b8 cd [2] a4 e2 }

  condition:
    any of them
}