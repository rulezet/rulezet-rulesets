rule TTP_XOR_QUAD_CurrentVersionRun_c47d {
  strings:
    $key_c47d = { 97 12 [2] b3 1c [2] 98 30 [2] b6 12 [2] a2 09 [2] ad 13 [2] b3 0e [2] b1 0f [2] aa 09 [2] b6 0e [2] aa 21 }

  condition:
    any of them
}