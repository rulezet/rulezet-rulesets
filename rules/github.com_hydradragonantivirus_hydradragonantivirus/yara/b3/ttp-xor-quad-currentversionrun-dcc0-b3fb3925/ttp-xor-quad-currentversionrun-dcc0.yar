rule TTP_XOR_QUAD_CurrentVersionRun_dcc0 {
  strings:
    $key_dcc0 = { 8f af [2] ab a1 [2] 80 8d [2] ae af [2] ba b4 [2] b5 ae [2] ab b3 [2] a9 b2 [2] b2 b4 [2] ae b3 [2] b2 9c }

  condition:
    any of them
}