rule TTP_XOR_QUAD_CurrentVersionRun_d06e {
  strings:
    $key_d06e = { 83 01 [2] a7 0f [2] 8c 23 [2] a2 01 [2] b6 1a [2] b9 00 [2] a7 1d [2] a5 1c [2] be 1a [2] a2 1d [2] be 32 }

  condition:
    any of them
}