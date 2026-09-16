rule TTP_XOR_QUAD_CurrentVersionRun_c256 {
  strings:
    $key_c256 = { 91 39 [2] b5 37 [2] 9e 1b [2] b0 39 [2] a4 22 [2] ab 38 [2] b5 25 [2] b7 24 [2] ac 22 [2] b0 25 [2] ac 0a }

  condition:
    any of them
}