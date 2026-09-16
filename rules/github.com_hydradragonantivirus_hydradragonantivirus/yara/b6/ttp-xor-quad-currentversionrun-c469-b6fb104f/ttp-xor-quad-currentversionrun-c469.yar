rule TTP_XOR_QUAD_CurrentVersionRun_c469 {
  strings:
    $key_c469 = { 97 06 [2] b3 08 [2] 98 24 [2] b6 06 [2] a2 1d [2] ad 07 [2] b3 1a [2] b1 1b [2] aa 1d [2] b6 1a [2] aa 35 }

  condition:
    any of them
}