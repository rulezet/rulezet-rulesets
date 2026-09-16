rule TTP_XOR_QUAD_CurrentVersionRun_d429 {
  strings:
    $key_d429 = { 87 46 [2] a3 48 [2] 88 64 [2] a6 46 [2] b2 5d [2] bd 47 [2] a3 5a [2] a1 5b [2] ba 5d [2] a6 5a [2] ba 75 }

  condition:
    any of them
}