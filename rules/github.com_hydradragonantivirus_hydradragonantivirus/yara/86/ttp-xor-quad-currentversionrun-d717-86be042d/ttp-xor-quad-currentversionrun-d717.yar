rule TTP_XOR_QUAD_CurrentVersionRun_d717 {
  strings:
    $key_d717 = { 84 78 [2] a0 76 [2] 8b 5a [2] a5 78 [2] b1 63 [2] be 79 [2] a0 64 [2] a2 65 [2] b9 63 [2] a5 64 [2] b9 4b }

  condition:
    any of them
}