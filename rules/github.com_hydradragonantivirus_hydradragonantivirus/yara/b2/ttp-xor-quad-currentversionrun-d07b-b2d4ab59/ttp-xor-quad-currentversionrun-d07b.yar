rule TTP_XOR_QUAD_CurrentVersionRun_d07b {
  strings:
    $key_d07b = { 83 14 [2] a7 1a [2] 8c 36 [2] a2 14 [2] b6 0f [2] b9 15 [2] a7 08 [2] a5 09 [2] be 0f [2] a2 08 [2] be 27 }

  condition:
    any of them
}