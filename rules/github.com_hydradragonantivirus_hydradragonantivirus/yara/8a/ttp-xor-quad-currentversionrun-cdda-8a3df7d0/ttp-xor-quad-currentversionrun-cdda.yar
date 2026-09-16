rule TTP_XOR_QUAD_CurrentVersionRun_cdda {
  strings:
    $key_cdda = { 9e b5 [2] ba bb [2] 91 97 [2] bf b5 [2] ab ae [2] a4 b4 [2] ba a9 [2] b8 a8 [2] a3 ae [2] bf a9 [2] a3 86 }

  condition:
    any of them
}