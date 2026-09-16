rule TTP_XOR_QUAD_CurrentVersionRun_dc96 {
  strings:
    $key_dc96 = { 8f f9 [2] ab f7 [2] 80 db [2] ae f9 [2] ba e2 [2] b5 f8 [2] ab e5 [2] a9 e4 [2] b2 e2 [2] ae e5 [2] b2 ca }

  condition:
    any of them
}