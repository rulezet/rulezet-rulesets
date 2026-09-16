rule TTP_XOR_QUAD_CurrentVersionRun_4d0f {
  strings:
    $key_4d0f = { 1e 60 [2] 3a 6e [2] 11 42 [2] 3f 60 [2] 2b 7b [2] 24 61 [2] 3a 7c [2] 38 7d [2] 23 7b [2] 3f 7c [2] 23 53 }

  condition:
    any of them
}