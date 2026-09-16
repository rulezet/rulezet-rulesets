rule TTP_XOR_QUAD_CurrentVersionRun_e36e {
  strings:
    $key_e36e = { b0 01 [2] 94 0f [2] bf 23 [2] 91 01 [2] 85 1a [2] 8a 00 [2] 94 1d [2] 96 1c [2] 8d 1a [2] 91 1d [2] 8d 32 }

  condition:
    any of them
}