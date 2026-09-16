rule TTP_XOR_QUAD_CurrentVersionRun_c2fb {
  strings:
    $key_c2fb = { 91 94 [2] b5 9a [2] 9e b6 [2] b0 94 [2] a4 8f [2] ab 95 [2] b5 88 [2] b7 89 [2] ac 8f [2] b0 88 [2] ac a7 }

  condition:
    any of them
}