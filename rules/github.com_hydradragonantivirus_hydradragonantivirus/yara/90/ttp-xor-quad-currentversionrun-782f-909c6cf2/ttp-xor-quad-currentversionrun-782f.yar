rule TTP_XOR_QUAD_CurrentVersionRun_782f {
  strings:
    $key_782f = { 2b 40 [2] 0f 4e [2] 24 62 [2] 0a 40 [2] 1e 5b [2] 11 41 [2] 0f 5c [2] 0d 5d [2] 16 5b [2] 0a 5c [2] 16 73 }

  condition:
    any of them
}