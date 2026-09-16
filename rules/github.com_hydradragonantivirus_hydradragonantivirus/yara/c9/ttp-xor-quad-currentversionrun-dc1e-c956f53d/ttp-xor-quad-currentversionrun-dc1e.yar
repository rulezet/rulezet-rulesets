rule TTP_XOR_QUAD_CurrentVersionRun_dc1e {
  strings:
    $key_dc1e = { 8f 71 [2] ab 7f [2] 80 53 [2] ae 71 [2] ba 6a [2] b5 70 [2] ab 6d [2] a9 6c [2] b2 6a [2] ae 6d [2] b2 42 }

  condition:
    any of them
}