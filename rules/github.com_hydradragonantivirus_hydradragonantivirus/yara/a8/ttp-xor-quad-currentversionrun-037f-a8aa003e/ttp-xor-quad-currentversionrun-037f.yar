rule TTP_XOR_QUAD_CurrentVersionRun_037f {
  strings:
    $key_037f = { 50 10 [2] 74 1e [2] 5f 32 [2] 71 10 [2] 65 0b [2] 6a 11 [2] 74 0c [2] 76 0d [2] 6d 0b [2] 71 0c [2] 6d 23 }

  condition:
    any of them
}