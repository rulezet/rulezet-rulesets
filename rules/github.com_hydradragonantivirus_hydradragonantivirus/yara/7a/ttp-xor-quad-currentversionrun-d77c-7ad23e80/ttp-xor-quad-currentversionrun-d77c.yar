rule TTP_XOR_QUAD_CurrentVersionRun_d77c {
  strings:
    $key_d77c = { 84 13 [2] a0 1d [2] 8b 31 [2] a5 13 [2] b1 08 [2] be 12 [2] a0 0f [2] a2 0e [2] b9 08 [2] a5 0f [2] b9 20 }

  condition:
    any of them
}