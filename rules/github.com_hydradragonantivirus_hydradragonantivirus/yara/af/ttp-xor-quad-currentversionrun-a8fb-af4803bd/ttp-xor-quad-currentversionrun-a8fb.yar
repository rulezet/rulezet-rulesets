rule TTP_XOR_QUAD_CurrentVersionRun_a8fb {
  strings:
    $key_a8fb = { fb 94 [2] df 9a [2] f4 b6 [2] da 94 [2] ce 8f [2] c1 95 [2] df 88 [2] dd 89 [2] c6 8f [2] da 88 [2] c6 a7 }

  condition:
    any of them
}