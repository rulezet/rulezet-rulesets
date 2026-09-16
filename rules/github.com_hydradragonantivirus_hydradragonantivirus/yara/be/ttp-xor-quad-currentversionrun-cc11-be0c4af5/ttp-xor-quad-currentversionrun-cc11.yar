rule TTP_XOR_QUAD_CurrentVersionRun_cc11 {
  strings:
    $key_cc11 = { 9f 7e [2] bb 70 [2] 90 5c [2] be 7e [2] aa 65 [2] a5 7f [2] bb 62 [2] b9 63 [2] a2 65 [2] be 62 [2] a2 4d }

  condition:
    any of them
}