rule TTP_XOR_QUAD_CurrentVersionRun_730f {
  strings:
    $key_730f = { 20 60 [2] 04 6e [2] 2f 42 [2] 01 60 [2] 15 7b [2] 1a 61 [2] 04 7c [2] 06 7d [2] 1d 7b [2] 01 7c [2] 1d 53 }

  condition:
    any of them
}