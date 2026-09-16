rule TTP_XOR_QUAD_CurrentVersionRun_dce2 {
  strings:
    $key_dce2 = { 8f 8d [2] ab 83 [2] 80 af [2] ae 8d [2] ba 96 [2] b5 8c [2] ab 91 [2] a9 90 [2] b2 96 [2] ae 91 [2] b2 be }

  condition:
    any of them
}