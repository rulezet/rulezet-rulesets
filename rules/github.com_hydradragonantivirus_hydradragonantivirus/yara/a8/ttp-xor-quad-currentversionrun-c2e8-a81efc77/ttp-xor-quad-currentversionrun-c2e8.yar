rule TTP_XOR_QUAD_CurrentVersionRun_c2e8 {
  strings:
    $key_c2e8 = { 91 87 [2] b5 89 [2] 9e a5 [2] b0 87 [2] a4 9c [2] ab 86 [2] b5 9b [2] b7 9a [2] ac 9c [2] b0 9b [2] ac b4 }

  condition:
    any of them
}