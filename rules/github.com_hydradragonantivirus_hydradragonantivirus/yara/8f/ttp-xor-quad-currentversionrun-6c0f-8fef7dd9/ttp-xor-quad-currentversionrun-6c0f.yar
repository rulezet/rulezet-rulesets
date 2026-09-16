rule TTP_XOR_QUAD_CurrentVersionRun_6c0f {
  strings:
    $key_6c0f = { 3f 60 [2] 1b 6e [2] 30 42 [2] 1e 60 [2] 0a 7b [2] 05 61 [2] 1b 7c [2] 19 7d [2] 02 7b [2] 1e 7c [2] 02 53 }

  condition:
    any of them
}