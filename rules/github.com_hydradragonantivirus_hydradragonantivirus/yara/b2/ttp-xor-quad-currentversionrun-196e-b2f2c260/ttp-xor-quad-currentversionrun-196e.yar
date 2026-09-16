rule TTP_XOR_QUAD_CurrentVersionRun_196e {
  strings:
    $key_196e = { 4a 01 [2] 6e 0f [2] 45 23 [2] 6b 01 [2] 7f 1a [2] 70 00 [2] 6e 1d [2] 6c 1c [2] 77 1a [2] 6b 1d [2] 77 32 }

  condition:
    any of them
}