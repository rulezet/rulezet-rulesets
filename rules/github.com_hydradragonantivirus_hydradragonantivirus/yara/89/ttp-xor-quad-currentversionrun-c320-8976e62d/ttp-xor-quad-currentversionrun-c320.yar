rule TTP_XOR_QUAD_CurrentVersionRun_c320 {
  strings:
    $key_c320 = { 90 4f [2] b4 41 [2] 9f 6d [2] b1 4f [2] a5 54 [2] aa 4e [2] b4 53 [2] b6 52 [2] ad 54 [2] b1 53 [2] ad 7c }

  condition:
    any of them
}