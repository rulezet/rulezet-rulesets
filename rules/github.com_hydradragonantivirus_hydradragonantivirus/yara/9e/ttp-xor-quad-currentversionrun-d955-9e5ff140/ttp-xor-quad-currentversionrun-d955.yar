rule TTP_XOR_QUAD_CurrentVersionRun_d955 {
  strings:
    $key_d955 = { 8a 3a [2] ae 34 [2] 85 18 [2] ab 3a [2] bf 21 [2] b0 3b [2] ae 26 [2] ac 27 [2] b7 21 [2] ab 26 [2] b7 09 }

  condition:
    any of them
}