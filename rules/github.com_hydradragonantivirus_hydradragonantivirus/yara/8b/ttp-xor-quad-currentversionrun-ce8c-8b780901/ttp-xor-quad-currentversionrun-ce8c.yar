rule TTP_XOR_QUAD_CurrentVersionRun_ce8c {
  strings:
    $key_ce8c = { 9d e3 [2] b9 ed [2] 92 c1 [2] bc e3 [2] a8 f8 [2] a7 e2 [2] b9 ff [2] bb fe [2] a0 f8 [2] bc ff [2] a0 d0 }

  condition:
    any of them
}