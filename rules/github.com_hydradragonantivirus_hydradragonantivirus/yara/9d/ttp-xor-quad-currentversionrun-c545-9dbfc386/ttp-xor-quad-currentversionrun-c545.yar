rule TTP_XOR_QUAD_CurrentVersionRun_c545 {
  strings:
    $key_c545 = { 96 2a [2] b2 24 [2] 99 08 [2] b7 2a [2] a3 31 [2] ac 2b [2] b2 36 [2] b0 37 [2] ab 31 [2] b7 36 [2] ab 19 }

  condition:
    any of them
}