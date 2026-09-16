rule TTP_XOR_QUAD_CurrentVersionRun_d7eb {
  strings:
    $key_d7eb = { 84 84 [2] a0 8a [2] 8b a6 [2] a5 84 [2] b1 9f [2] be 85 [2] a0 98 [2] a2 99 [2] b9 9f [2] a5 98 [2] b9 b7 }

  condition:
    any of them
}