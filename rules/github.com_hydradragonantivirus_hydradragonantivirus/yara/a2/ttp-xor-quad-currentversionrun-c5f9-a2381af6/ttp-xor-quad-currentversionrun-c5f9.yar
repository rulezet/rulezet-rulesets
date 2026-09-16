rule TTP_XOR_QUAD_CurrentVersionRun_c5f9 {
  strings:
    $key_c5f9 = { 96 96 [2] b2 98 [2] 99 b4 [2] b7 96 [2] a3 8d [2] ac 97 [2] b2 8a [2] b0 8b [2] ab 8d [2] b7 8a [2] ab a5 }

  condition:
    any of them
}