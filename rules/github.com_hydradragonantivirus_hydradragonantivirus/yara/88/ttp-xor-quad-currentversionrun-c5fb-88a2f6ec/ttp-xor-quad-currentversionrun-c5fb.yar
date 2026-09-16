rule TTP_XOR_QUAD_CurrentVersionRun_c5fb {
  strings:
    $key_c5fb = { 96 94 [2] b2 9a [2] 99 b6 [2] b7 94 [2] a3 8f [2] ac 95 [2] b2 88 [2] b0 89 [2] ab 8f [2] b7 88 [2] ab a7 }

  condition:
    any of them
}