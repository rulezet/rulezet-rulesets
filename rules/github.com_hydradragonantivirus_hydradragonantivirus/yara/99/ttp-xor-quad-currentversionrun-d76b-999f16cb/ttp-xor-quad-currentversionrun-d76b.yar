rule TTP_XOR_QUAD_CurrentVersionRun_d76b {
  strings:
    $key_d76b = { 84 04 [2] a0 0a [2] 8b 26 [2] a5 04 [2] b1 1f [2] be 05 [2] a0 18 [2] a2 19 [2] b9 1f [2] a5 18 [2] b9 37 }

  condition:
    any of them
}