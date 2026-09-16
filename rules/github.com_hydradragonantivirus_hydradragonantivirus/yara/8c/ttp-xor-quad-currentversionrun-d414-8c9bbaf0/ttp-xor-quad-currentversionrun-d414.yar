rule TTP_XOR_QUAD_CurrentVersionRun_d414 {
  strings:
    $key_d414 = { 87 7b [2] a3 75 [2] 88 59 [2] a6 7b [2] b2 60 [2] bd 7a [2] a3 67 [2] a1 66 [2] ba 60 [2] a6 67 [2] ba 48 }

  condition:
    any of them
}