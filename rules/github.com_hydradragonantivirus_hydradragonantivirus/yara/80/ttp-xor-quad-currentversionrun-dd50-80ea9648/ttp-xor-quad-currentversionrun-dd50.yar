rule TTP_XOR_QUAD_CurrentVersionRun_dd50 {
  strings:
    $key_dd50 = { 8e 3f [2] aa 31 [2] 81 1d [2] af 3f [2] bb 24 [2] b4 3e [2] aa 23 [2] a8 22 [2] b3 24 [2] af 23 [2] b3 0c }

  condition:
    any of them
}