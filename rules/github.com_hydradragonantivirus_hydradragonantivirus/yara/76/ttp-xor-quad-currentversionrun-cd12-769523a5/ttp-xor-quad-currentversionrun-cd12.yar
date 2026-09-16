rule TTP_XOR_QUAD_CurrentVersionRun_cd12 {
  strings:
    $key_cd12 = { 9e 7d [2] ba 73 [2] 91 5f [2] bf 7d [2] ab 66 [2] a4 7c [2] ba 61 [2] b8 60 [2] a3 66 [2] bf 61 [2] a3 4e }

  condition:
    any of them
}