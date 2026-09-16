rule TTP_XOR_QUAD_CurrentVersionRun_dcfe {
  strings:
    $key_dcfe = { 8f 91 [2] ab 9f [2] 80 b3 [2] ae 91 [2] ba 8a [2] b5 90 [2] ab 8d [2] a9 8c [2] b2 8a [2] ae 8d [2] b2 a2 }

  condition:
    any of them
}