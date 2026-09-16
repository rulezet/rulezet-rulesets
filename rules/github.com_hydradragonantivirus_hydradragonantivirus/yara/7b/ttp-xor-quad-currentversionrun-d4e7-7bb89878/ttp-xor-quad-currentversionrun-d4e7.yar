rule TTP_XOR_QUAD_CurrentVersionRun_d4e7 {
  strings:
    $key_d4e7 = { 87 88 [2] a3 86 [2] 88 aa [2] a6 88 [2] b2 93 [2] bd 89 [2] a3 94 [2] a1 95 [2] ba 93 [2] a6 94 [2] ba bb }

  condition:
    any of them
}