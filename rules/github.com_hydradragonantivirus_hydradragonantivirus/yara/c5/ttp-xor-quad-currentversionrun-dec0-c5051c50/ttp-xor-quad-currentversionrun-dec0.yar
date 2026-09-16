rule TTP_XOR_QUAD_CurrentVersionRun_dec0 {
  strings:
    $key_dec0 = { 8d af [2] a9 a1 [2] 82 8d [2] ac af [2] b8 b4 [2] b7 ae [2] a9 b3 [2] ab b2 [2] b0 b4 [2] ac b3 [2] b0 9c }

  condition:
    any of them
}