rule TTP_XOR_QUAD_CurrentVersionRun_7b0f {
  strings:
    $key_7b0f = { 28 60 [2] 0c 6e [2] 27 42 [2] 09 60 [2] 1d 7b [2] 12 61 [2] 0c 7c [2] 0e 7d [2] 15 7b [2] 09 7c [2] 15 53 }

  condition:
    any of them
}