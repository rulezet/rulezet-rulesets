rule TTP_XOR_QUAD_CurrentVersionRun_206e {
  strings:
    $key_206e = { 73 01 [2] 57 0f [2] 7c 23 [2] 52 01 [2] 46 1a [2] 49 00 [2] 57 1d [2] 55 1c [2] 4e 1a [2] 52 1d [2] 4e 32 }

  condition:
    any of them
}