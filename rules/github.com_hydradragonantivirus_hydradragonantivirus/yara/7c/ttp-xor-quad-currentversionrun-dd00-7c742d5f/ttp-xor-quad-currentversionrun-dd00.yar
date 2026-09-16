rule TTP_XOR_QUAD_CurrentVersionRun_dd00 {
  strings:
    $key_dd00 = { 8e 6f [2] aa 61 [2] 81 4d [2] af 6f [2] bb 74 [2] b4 6e [2] aa 73 [2] a8 72 [2] b3 74 [2] af 73 [2] b3 5c }

  condition:
    any of them
}