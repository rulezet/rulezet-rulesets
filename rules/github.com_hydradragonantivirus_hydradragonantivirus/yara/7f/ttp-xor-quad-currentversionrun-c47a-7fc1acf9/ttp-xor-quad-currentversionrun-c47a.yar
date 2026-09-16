rule TTP_XOR_QUAD_CurrentVersionRun_c47a {
  strings:
    $key_c47a = { 97 15 [2] b3 1b [2] 98 37 [2] b6 15 [2] a2 0e [2] ad 14 [2] b3 09 [2] b1 08 [2] aa 0e [2] b6 09 [2] aa 26 }

  condition:
    any of them
}