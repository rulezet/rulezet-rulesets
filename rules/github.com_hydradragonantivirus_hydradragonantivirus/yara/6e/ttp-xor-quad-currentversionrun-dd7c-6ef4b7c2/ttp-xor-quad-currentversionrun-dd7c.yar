rule TTP_XOR_QUAD_CurrentVersionRun_dd7c {
  strings:
    $key_dd7c = { 8e 13 [2] aa 1d [2] 81 31 [2] af 13 [2] bb 08 [2] b4 12 [2] aa 0f [2] a8 0e [2] b3 08 [2] af 0f [2] b3 20 }

  condition:
    any of them
}