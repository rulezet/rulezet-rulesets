rule TTP_XOR_QUAD_CurrentVersionRun_cc62 {
  strings:
    $key_cc62 = { 9f 0d [2] bb 03 [2] 90 2f [2] be 0d [2] aa 16 [2] a5 0c [2] bb 11 [2] b9 10 [2] a2 16 [2] be 11 [2] a2 3e }

  condition:
    any of them
}