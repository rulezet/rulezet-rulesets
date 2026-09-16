rule TTP_XOR_QUAD_CurrentVersionRun_cc5f {
  strings:
    $key_cc5f = { 9f 30 [2] bb 3e [2] 90 12 [2] be 30 [2] aa 2b [2] a5 31 [2] bb 2c [2] b9 2d [2] a2 2b [2] be 2c [2] a2 03 }

  condition:
    any of them
}