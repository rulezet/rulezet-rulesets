rule TTP_XOR_QUAD_CurrentVersionRun_c2e9 {
  strings:
    $key_c2e9 = { 91 86 [2] b5 88 [2] 9e a4 [2] b0 86 [2] a4 9d [2] ab 87 [2] b5 9a [2] b7 9b [2] ac 9d [2] b0 9a [2] ac b5 }

  condition:
    any of them
}