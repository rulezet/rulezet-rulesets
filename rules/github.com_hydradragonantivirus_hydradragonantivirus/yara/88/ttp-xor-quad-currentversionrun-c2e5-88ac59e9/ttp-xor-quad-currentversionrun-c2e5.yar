rule TTP_XOR_QUAD_CurrentVersionRun_c2e5 {
  strings:
    $key_c2e5 = { 91 8a [2] b5 84 [2] 9e a8 [2] b0 8a [2] a4 91 [2] ab 8b [2] b5 96 [2] b7 97 [2] ac 91 [2] b0 96 [2] ac b9 }

  condition:
    any of them
}