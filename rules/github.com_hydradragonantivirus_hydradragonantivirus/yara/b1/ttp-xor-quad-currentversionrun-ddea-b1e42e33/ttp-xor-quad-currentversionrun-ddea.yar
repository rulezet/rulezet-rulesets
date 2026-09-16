rule TTP_XOR_QUAD_CurrentVersionRun_ddea {
  strings:
    $key_ddea = { 8e 85 [2] aa 8b [2] 81 a7 [2] af 85 [2] bb 9e [2] b4 84 [2] aa 99 [2] a8 98 [2] b3 9e [2] af 99 [2] b3 b6 }

  condition:
    any of them
}