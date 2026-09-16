rule TTP_XOR_QUAD_CurrentVersionRun_d06b {
  strings:
    $key_d06b = { 83 04 [2] a7 0a [2] 8c 26 [2] a2 04 [2] b6 1f [2] b9 05 [2] a7 18 [2] a5 19 [2] be 1f [2] a2 18 [2] be 37 }

  condition:
    any of them
}