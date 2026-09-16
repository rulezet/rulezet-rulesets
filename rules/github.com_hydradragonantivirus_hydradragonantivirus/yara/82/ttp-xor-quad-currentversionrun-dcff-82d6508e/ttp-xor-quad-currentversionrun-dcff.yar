rule TTP_XOR_QUAD_CurrentVersionRun_dcff {
  strings:
    $key_dcff = { 8f 90 [2] ab 9e [2] 80 b2 [2] ae 90 [2] ba 8b [2] b5 91 [2] ab 8c [2] a9 8d [2] b2 8b [2] ae 8c [2] b2 a3 }

  condition:
    any of them
}