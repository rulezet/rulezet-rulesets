rule TTP_XOR_QUAD_CurrentVersionRun_c505 {
  strings:
    $key_c505 = { 96 6a [2] b2 64 [2] 99 48 [2] b7 6a [2] a3 71 [2] ac 6b [2] b2 76 [2] b0 77 [2] ab 71 [2] b7 76 [2] ab 59 }

  condition:
    any of them
}