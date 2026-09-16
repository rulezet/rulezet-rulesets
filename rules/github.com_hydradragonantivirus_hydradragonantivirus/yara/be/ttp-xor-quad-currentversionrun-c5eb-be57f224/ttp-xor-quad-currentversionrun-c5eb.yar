rule TTP_XOR_QUAD_CurrentVersionRun_c5eb {
  strings:
    $key_c5eb = { 96 84 [2] b2 8a [2] 99 a6 [2] b7 84 [2] a3 9f [2] ac 85 [2] b2 98 [2] b0 99 [2] ab 9f [2] b7 98 [2] ab b7 }

  condition:
    any of them
}