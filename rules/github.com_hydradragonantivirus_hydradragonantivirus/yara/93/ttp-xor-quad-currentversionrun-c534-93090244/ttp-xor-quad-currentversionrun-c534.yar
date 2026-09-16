rule TTP_XOR_QUAD_CurrentVersionRun_c534 {
  strings:
    $key_c534 = { 96 5b [2] b2 55 [2] 99 79 [2] b7 5b [2] a3 40 [2] ac 5a [2] b2 47 [2] b0 46 [2] ab 40 [2] b7 47 [2] ab 68 }

  condition:
    any of them
}