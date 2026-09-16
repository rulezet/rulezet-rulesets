rule TTP_XOR_QUAD_CurrentVersionRun_cf1e {
  strings:
    $key_cf1e = { 9c 71 [2] b8 7f [2] 93 53 [2] bd 71 [2] a9 6a [2] a6 70 [2] b8 6d [2] ba 6c [2] a1 6a [2] bd 6d [2] a1 42 }

  condition:
    any of them
}