rule TTP_XOR_QUAD_CurrentVersionRun_dce7 {
  strings:
    $key_dce7 = { 8f 88 [2] ab 86 [2] 80 aa [2] ae 88 [2] ba 93 [2] b5 89 [2] ab 94 [2] a9 95 [2] b2 93 [2] ae 94 [2] b2 bb }

  condition:
    any of them
}