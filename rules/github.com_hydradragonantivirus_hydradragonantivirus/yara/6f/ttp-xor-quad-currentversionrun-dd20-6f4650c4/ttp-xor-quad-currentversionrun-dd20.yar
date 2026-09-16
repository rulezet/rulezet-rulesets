rule TTP_XOR_QUAD_CurrentVersionRun_dd20 {
  strings:
    $key_dd20 = { 8e 4f [2] aa 41 [2] 81 6d [2] af 4f [2] bb 54 [2] b4 4e [2] aa 53 [2] a8 52 [2] b3 54 [2] af 53 [2] b3 7c }

  condition:
    any of them
}