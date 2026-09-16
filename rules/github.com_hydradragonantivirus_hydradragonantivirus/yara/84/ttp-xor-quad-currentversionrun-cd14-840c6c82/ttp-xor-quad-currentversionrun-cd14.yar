rule TTP_XOR_QUAD_CurrentVersionRun_cd14 {
  strings:
    $key_cd14 = { 9e 7b [2] ba 75 [2] 91 59 [2] bf 7b [2] ab 60 [2] a4 7a [2] ba 67 [2] b8 66 [2] a3 60 [2] bf 67 [2] a3 48 }

  condition:
    any of them
}