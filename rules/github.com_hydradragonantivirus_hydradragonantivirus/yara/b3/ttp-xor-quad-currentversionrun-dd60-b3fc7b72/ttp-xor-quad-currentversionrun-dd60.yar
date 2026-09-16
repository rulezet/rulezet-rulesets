rule TTP_XOR_QUAD_CurrentVersionRun_dd60 {
  strings:
    $key_dd60 = { 8e 0f [2] aa 01 [2] 81 2d [2] af 0f [2] bb 14 [2] b4 0e [2] aa 13 [2] a8 12 [2] b3 14 [2] af 13 [2] b3 3c }

  condition:
    any of them
}