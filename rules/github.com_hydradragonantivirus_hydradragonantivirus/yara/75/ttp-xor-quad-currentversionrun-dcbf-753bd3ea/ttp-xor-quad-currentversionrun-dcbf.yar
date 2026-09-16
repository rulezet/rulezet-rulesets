rule TTP_XOR_QUAD_CurrentVersionRun_dcbf {
  strings:
    $key_dcbf = { 8f d0 [2] ab de [2] 80 f2 [2] ae d0 [2] ba cb [2] b5 d1 [2] ab cc [2] a9 cd [2] b2 cb [2] ae cc [2] b2 e3 }

  condition:
    any of them
}