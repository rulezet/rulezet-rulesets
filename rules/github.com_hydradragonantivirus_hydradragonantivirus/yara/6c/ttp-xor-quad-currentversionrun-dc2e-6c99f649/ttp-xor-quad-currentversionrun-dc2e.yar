rule TTP_XOR_QUAD_CurrentVersionRun_dc2e {
  strings:
    $key_dc2e = { 8f 41 [2] ab 4f [2] 80 63 [2] ae 41 [2] ba 5a [2] b5 40 [2] ab 5d [2] a9 5c [2] b2 5a [2] ae 5d [2] b2 72 }

  condition:
    any of them
}