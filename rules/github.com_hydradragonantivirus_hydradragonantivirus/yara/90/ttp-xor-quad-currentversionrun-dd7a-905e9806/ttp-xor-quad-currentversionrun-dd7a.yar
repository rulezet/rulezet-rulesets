rule TTP_XOR_QUAD_CurrentVersionRun_dd7a {
  strings:
    $key_dd7a = { 8e 15 [2] aa 1b [2] 81 37 [2] af 15 [2] bb 0e [2] b4 14 [2] aa 09 [2] a8 08 [2] b3 0e [2] af 09 [2] b3 26 }

  condition:
    any of them
}