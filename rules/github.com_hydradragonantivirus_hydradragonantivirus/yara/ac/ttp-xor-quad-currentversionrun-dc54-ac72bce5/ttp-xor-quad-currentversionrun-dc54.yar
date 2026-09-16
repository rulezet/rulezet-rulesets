rule TTP_XOR_QUAD_CurrentVersionRun_dc54 {
  strings:
    $key_dc54 = { 8f 3b [2] ab 35 [2] 80 19 [2] ae 3b [2] ba 20 [2] b5 3a [2] ab 27 [2] a9 26 [2] b2 20 [2] ae 27 [2] b2 08 }

  condition:
    any of them
}