rule TTP_XOR_QUAD_CurrentVersionRun_e56e {
  strings:
    $key_e56e = { b6 01 [2] 92 0f [2] b9 23 [2] 97 01 [2] 83 1a [2] 8c 00 [2] 92 1d [2] 90 1c [2] 8b 1a [2] 97 1d [2] 8b 32 }

  condition:
    any of them
}