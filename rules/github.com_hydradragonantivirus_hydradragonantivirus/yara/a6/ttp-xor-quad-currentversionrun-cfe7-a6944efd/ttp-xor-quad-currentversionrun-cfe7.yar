rule TTP_XOR_QUAD_CurrentVersionRun_cfe7 {
  strings:
    $key_cfe7 = { 9c 88 [2] b8 86 [2] 93 aa [2] bd 88 [2] a9 93 [2] a6 89 [2] b8 94 [2] ba 95 [2] a1 93 [2] bd 94 [2] a1 bb }

  condition:
    any of them
}