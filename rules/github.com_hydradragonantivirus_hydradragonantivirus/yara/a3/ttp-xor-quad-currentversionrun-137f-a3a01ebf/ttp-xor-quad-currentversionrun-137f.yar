rule TTP_XOR_QUAD_CurrentVersionRun_137f {
  strings:
    $key_137f = { 40 10 [2] 64 1e [2] 4f 32 [2] 61 10 [2] 75 0b [2] 7a 11 [2] 64 0c [2] 66 0d [2] 7d 0b [2] 61 0c [2] 7d 23 }

  condition:
    any of them
}