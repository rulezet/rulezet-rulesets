rule TTP_XOR_QUAD_CurrentVersionRun_c36e {
  strings:
    $key_c36e = { 90 01 [2] b4 0f [2] 9f 23 [2] b1 01 [2] a5 1a [2] aa 00 [2] b4 1d [2] b6 1c [2] ad 1a [2] b1 1d [2] ad 32 }

  condition:
    any of them
}