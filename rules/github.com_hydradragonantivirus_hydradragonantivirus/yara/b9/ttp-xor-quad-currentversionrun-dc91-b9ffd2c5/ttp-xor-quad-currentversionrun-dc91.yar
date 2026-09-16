rule TTP_XOR_QUAD_CurrentVersionRun_dc91 {
  strings:
    $key_dc91 = { 8f fe [2] ab f0 [2] 80 dc [2] ae fe [2] ba e5 [2] b5 ff [2] ab e2 [2] a9 e3 [2] b2 e5 [2] ae e2 [2] b2 cd }

  condition:
    any of them
}