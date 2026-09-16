rule TTP_XOR_QUAD_CurrentVersionRun_006e {
  strings:
    $key_006e = { 53 01 [2] 77 0f [2] 5c 23 [2] 72 01 [2] 66 1a [2] 69 00 [2] 77 1d [2] 75 1c [2] 6e 1a [2] 72 1d [2] 6e 32 }

  condition:
    any of them
}