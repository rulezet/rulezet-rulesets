rule TTP_XOR_QUAD_CurrentVersionRun_d77b {
  strings:
    $key_d77b = { 84 14 [2] a0 1a [2] 8b 36 [2] a5 14 [2] b1 0f [2] be 15 [2] a0 08 [2] a2 09 [2] b9 0f [2] a5 08 [2] b9 27 }

  condition:
    any of them
}