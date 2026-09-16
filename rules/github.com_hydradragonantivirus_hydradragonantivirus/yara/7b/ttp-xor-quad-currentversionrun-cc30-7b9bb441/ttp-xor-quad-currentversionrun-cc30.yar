rule TTP_XOR_QUAD_CurrentVersionRun_cc30 {
  strings:
    $key_cc30 = { 9f 5f [2] bb 51 [2] 90 7d [2] be 5f [2] aa 44 [2] a5 5e [2] bb 43 [2] b9 42 [2] a2 44 [2] be 43 [2] a2 6c }

  condition:
    any of them
}