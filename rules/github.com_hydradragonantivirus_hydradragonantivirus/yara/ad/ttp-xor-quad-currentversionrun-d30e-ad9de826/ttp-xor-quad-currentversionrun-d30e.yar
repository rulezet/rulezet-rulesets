rule TTP_XOR_QUAD_CurrentVersionRun_d30e {
  strings:
    $key_d30e = { 80 61 [2] a4 6f [2] 8f 43 [2] a1 61 [2] b5 7a [2] ba 60 [2] a4 7d [2] a6 7c [2] bd 7a [2] a1 7d [2] bd 52 }

  condition:
    any of them
}