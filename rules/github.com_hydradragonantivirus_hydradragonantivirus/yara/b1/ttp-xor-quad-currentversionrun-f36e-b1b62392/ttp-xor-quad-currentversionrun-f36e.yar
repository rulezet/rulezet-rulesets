rule TTP_XOR_QUAD_CurrentVersionRun_f36e {
  strings:
    $key_f36e = { a0 01 [2] 84 0f [2] af 23 [2] 81 01 [2] 95 1a [2] 9a 00 [2] 84 1d [2] 86 1c [2] 9d 1a [2] 81 1d [2] 9d 32 }

  condition:
    any of them
}