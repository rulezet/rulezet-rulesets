rule TTP_XOR_QUAD_CurrentVersionRun_ed6e {
  strings:
    $key_ed6e = { be 01 [2] 9a 0f [2] b1 23 [2] 9f 01 [2] 8b 1a [2] 84 00 [2] 9a 1d [2] 98 1c [2] 83 1a [2] 9f 1d [2] 83 32 }

  condition:
    any of them
}