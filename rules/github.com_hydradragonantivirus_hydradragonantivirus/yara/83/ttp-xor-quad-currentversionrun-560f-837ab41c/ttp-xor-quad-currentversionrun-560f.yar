rule TTP_XOR_QUAD_CurrentVersionRun_560f {
  strings:
    $key_560f = { 05 60 [2] 21 6e [2] 0a 42 [2] 24 60 [2] 30 7b [2] 3f 61 [2] 21 7c [2] 23 7d [2] 38 7b [2] 24 7c [2] 38 53 }

  condition:
    any of them
}