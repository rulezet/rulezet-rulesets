rule TTP_XOR_QUAD_CurrentVersionRun_4c0f {
  strings:
    $key_4c0f = { 1f 60 [2] 3b 6e [2] 10 42 [2] 3e 60 [2] 2a 7b [2] 25 61 [2] 3b 7c [2] 39 7d [2] 22 7b [2] 3e 7c [2] 22 53 }

  condition:
    any of them
}