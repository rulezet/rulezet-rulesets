rule TTP_XOR_QUAD_CurrentVersionRun_3f6e {
  strings:
    $key_3f6e = { 6c 01 [2] 48 0f [2] 63 23 [2] 4d 01 [2] 59 1a [2] 56 00 [2] 48 1d [2] 4a 1c [2] 51 1a [2] 4d 1d [2] 51 32 }

  condition:
    any of them
}