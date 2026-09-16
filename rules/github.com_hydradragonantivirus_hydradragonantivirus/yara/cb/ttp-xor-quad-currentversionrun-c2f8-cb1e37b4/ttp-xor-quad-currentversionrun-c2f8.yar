rule TTP_XOR_QUAD_CurrentVersionRun_c2f8 {
  strings:
    $key_c2f8 = { 91 97 [2] b5 99 [2] 9e b5 [2] b0 97 [2] a4 8c [2] ab 96 [2] b5 8b [2] b7 8a [2] ac 8c [2] b0 8b [2] ac a4 }

  condition:
    any of them
}