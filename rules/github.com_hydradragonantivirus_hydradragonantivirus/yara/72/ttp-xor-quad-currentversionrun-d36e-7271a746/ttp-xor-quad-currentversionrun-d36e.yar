rule TTP_XOR_QUAD_CurrentVersionRun_d36e {
  strings:
    $key_d36e = { 80 01 [2] a4 0f [2] 8f 23 [2] a1 01 [2] b5 1a [2] ba 00 [2] a4 1d [2] a6 1c [2] bd 1a [2] a1 1d [2] bd 32 }

  condition:
    any of them
}