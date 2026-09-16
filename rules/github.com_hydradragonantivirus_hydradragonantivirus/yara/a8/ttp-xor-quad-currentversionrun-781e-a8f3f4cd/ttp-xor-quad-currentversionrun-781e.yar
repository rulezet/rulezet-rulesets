rule TTP_XOR_QUAD_CurrentVersionRun_781e {
  strings:
    $key_781e = { 2b 71 [2] 0f 7f [2] 24 53 [2] 0a 71 [2] 1e 6a [2] 11 70 [2] 0f 6d [2] 0d 6c [2] 16 6a [2] 0a 6d [2] 16 42 }

  condition:
    any of them
}