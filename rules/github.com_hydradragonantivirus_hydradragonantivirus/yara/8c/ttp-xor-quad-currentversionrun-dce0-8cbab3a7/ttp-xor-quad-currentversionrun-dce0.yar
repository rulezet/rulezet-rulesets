rule TTP_XOR_QUAD_CurrentVersionRun_dce0 {
  strings:
    $key_dce0 = { 8f 8f [2] ab 81 [2] 80 ad [2] ae 8f [2] ba 94 [2] b5 8e [2] ab 93 [2] a9 92 [2] b2 94 [2] ae 93 [2] b2 bc }

  condition:
    any of them
}