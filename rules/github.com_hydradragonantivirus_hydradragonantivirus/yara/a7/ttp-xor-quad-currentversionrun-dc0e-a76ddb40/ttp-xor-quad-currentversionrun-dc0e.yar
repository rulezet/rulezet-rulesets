rule TTP_XOR_QUAD_CurrentVersionRun_dc0e {
  strings:
    $key_dc0e = { 8f 61 [2] ab 6f [2] 80 43 [2] ae 61 [2] ba 7a [2] b5 60 [2] ab 7d [2] a9 7c [2] b2 7a [2] ae 7d [2] b2 52 }

  condition:
    any of them
}