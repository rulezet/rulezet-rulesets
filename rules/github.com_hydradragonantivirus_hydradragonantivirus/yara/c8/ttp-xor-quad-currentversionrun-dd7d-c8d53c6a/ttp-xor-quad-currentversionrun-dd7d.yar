rule TTP_XOR_QUAD_CurrentVersionRun_dd7d {
  strings:
    $key_dd7d = { 8e 12 [2] aa 1c [2] 81 30 [2] af 12 [2] bb 09 [2] b4 13 [2] aa 0e [2] a8 0f [2] b3 09 [2] af 0e [2] b3 21 }

  condition:
    any of them
}