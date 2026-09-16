rule TTP_XOR_QUAD_CurrentVersionRun_cc42 {
  strings:
    $key_cc42 = { 9f 2d [2] bb 23 [2] 90 0f [2] be 2d [2] aa 36 [2] a5 2c [2] bb 31 [2] b9 30 [2] a2 36 [2] be 31 [2] a2 1e }

  condition:
    any of them
}