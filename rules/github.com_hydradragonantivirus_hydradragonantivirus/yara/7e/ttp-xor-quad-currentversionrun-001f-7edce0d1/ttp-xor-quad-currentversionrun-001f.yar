rule TTP_XOR_QUAD_CurrentVersionRun_001f {
  strings:
    $key_001f = { 53 70 [2] 77 7e [2] 5c 52 [2] 72 70 [2] 66 6b [2] 69 71 [2] 77 6c [2] 75 6d [2] 6e 6b [2] 72 6c [2] 6e 43 }

  condition:
    any of them
}