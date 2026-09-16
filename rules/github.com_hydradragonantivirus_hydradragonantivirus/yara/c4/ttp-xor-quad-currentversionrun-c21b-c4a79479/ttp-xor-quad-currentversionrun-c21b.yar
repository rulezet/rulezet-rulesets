rule TTP_XOR_QUAD_CurrentVersionRun_c21b {
  strings:
    $key_c21b = { 91 74 [2] b5 7a [2] 9e 56 [2] b0 74 [2] a4 6f [2] ab 75 [2] b5 68 [2] b7 69 [2] ac 6f [2] b0 68 [2] ac 47 }

  condition:
    any of them
}