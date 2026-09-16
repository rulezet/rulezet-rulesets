rule TTP_XOR_QUAD_CurrentVersionRun_d86e {
  strings:
    $key_d86e = { 8b 01 [2] af 0f [2] 84 23 [2] aa 01 [2] be 1a [2] b1 00 [2] af 1d [2] ad 1c [2] b6 1a [2] aa 1d [2] b6 32 }

  condition:
    any of them
}