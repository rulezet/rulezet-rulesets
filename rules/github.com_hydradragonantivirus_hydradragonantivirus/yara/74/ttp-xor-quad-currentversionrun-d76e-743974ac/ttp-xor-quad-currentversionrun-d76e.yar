rule TTP_XOR_QUAD_CurrentVersionRun_d76e {
  strings:
    $key_d76e = { 84 01 [2] a0 0f [2] 8b 23 [2] a5 01 [2] b1 1a [2] be 00 [2] a0 1d [2] a2 1c [2] b9 1a [2] a5 1d [2] b9 32 }

  condition:
    any of them
}