rule TTP_XOR_QUAD_CurrentVersionRun_c51b {
  strings:
    $key_c51b = { 96 74 [2] b2 7a [2] 99 56 [2] b7 74 [2] a3 6f [2] ac 75 [2] b2 68 [2] b0 69 [2] ab 6f [2] b7 68 [2] ab 47 }

  condition:
    any of them
}