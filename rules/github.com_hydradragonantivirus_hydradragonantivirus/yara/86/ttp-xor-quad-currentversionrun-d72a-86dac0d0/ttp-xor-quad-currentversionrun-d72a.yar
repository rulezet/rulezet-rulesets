rule TTP_XOR_QUAD_CurrentVersionRun_d72a {
  strings:
    $key_d72a = { 84 45 [2] a0 4b [2] 8b 67 [2] a5 45 [2] b1 5e [2] be 44 [2] a0 59 [2] a2 58 [2] b9 5e [2] a5 59 [2] b9 76 }

  condition:
    any of them
}