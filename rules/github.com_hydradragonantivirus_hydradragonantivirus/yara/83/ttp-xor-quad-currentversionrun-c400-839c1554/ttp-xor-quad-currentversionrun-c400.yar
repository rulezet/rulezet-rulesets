rule TTP_XOR_QUAD_CurrentVersionRun_c400 {
  strings:
    $key_c400 = { 97 6f [2] b3 61 [2] 98 4d [2] b6 6f [2] a2 74 [2] ad 6e [2] b3 73 [2] b1 72 [2] aa 74 [2] b6 73 [2] aa 5c }

  condition:
    any of them
}