rule TTP_XOR_QUAD_CurrentVersionRun_c548 {
  strings:
    $key_c548 = { 96 27 [2] b2 29 [2] 99 05 [2] b7 27 [2] a3 3c [2] ac 26 [2] b2 3b [2] b0 3a [2] ab 3c [2] b7 3b [2] ab 14 }

  condition:
    any of them
}