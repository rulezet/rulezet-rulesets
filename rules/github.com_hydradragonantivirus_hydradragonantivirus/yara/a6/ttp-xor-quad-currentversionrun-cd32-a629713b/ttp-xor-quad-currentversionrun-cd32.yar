rule TTP_XOR_QUAD_CurrentVersionRun_cd32 {
  strings:
    $key_cd32 = { 9e 5d [2] ba 53 [2] 91 7f [2] bf 5d [2] ab 46 [2] a4 5c [2] ba 41 [2] b8 40 [2] a3 46 [2] bf 41 [2] a3 6e }

  condition:
    any of them
}