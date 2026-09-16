rule TTP_XOR_QUAD_CurrentVersionRun_c1eb {
  strings:
    $key_c1eb = { 92 84 [2] b6 8a [2] 9d a6 [2] b3 84 [2] a7 9f [2] a8 85 [2] b6 98 [2] b4 99 [2] af 9f [2] b3 98 [2] af b7 }

  condition:
    any of them
}