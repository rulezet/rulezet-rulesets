rule TTP_XOR_QUAD_CurrentVersionRun_d776 {
  strings:
    $key_d776 = { 84 19 [2] a0 17 [2] 8b 3b [2] a5 19 [2] b1 02 [2] be 18 [2] a0 05 [2] a2 04 [2] b9 02 [2] a5 05 [2] b9 2a }

  condition:
    any of them
}