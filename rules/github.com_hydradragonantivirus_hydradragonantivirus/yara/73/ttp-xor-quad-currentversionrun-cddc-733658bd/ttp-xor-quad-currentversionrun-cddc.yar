rule TTP_XOR_QUAD_CurrentVersionRun_cddc {
  strings:
    $key_cddc = { 9e b3 [2] ba bd [2] 91 91 [2] bf b3 [2] ab a8 [2] a4 b2 [2] ba af [2] b8 ae [2] a3 a8 [2] bf af [2] a3 80 }

  condition:
    any of them
}