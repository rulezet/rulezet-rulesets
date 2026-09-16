rule TTP_XOR_QUAD_CurrentVersionRun_136e {
  strings:
    $key_136e = { 40 01 [2] 64 0f [2] 4f 23 [2] 61 01 [2] 75 1a [2] 7a 00 [2] 64 1d [2] 66 1c [2] 7d 1a [2] 61 1d [2] 7d 32 }

  condition:
    any of them
}