rule TTP_XOR_QUAD_CurrentVersionRun_c47c {
  strings:
    $key_c47c = { 97 13 [2] b3 1d [2] 98 31 [2] b6 13 [2] a2 08 [2] ad 12 [2] b3 0f [2] b1 0e [2] aa 08 [2] b6 0f [2] aa 20 }

  condition:
    any of them
}