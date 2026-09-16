rule TTP_XOR_QUAD_CurrentVersionRun_780f {
  strings:
    $key_780f = { 2b 60 [2] 0f 6e [2] 24 42 [2] 0a 60 [2] 1e 7b [2] 11 61 [2] 0f 7c [2] 0d 7d [2] 16 7b [2] 0a 7c [2] 16 53 }

  condition:
    any of them
}