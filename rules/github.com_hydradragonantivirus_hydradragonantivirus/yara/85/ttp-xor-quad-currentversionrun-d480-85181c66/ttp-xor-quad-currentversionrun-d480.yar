rule TTP_XOR_QUAD_CurrentVersionRun_d480 {
  strings:
    $key_d480 = { 87 ef [2] a3 e1 [2] 88 cd [2] a6 ef [2] b2 f4 [2] bd ee [2] a3 f3 [2] a1 f2 [2] ba f4 [2] a6 f3 [2] ba dc }

  condition:
    any of them
}