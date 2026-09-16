rule TTP_XOR_QUAD_CurrentVersionRun_1f0f {
  strings:
    $key_1f0f = { 4c 60 [2] 68 6e [2] 43 42 [2] 6d 60 [2] 79 7b [2] 76 61 [2] 68 7c [2] 6a 7d [2] 71 7b [2] 6d 7c [2] 71 53 }

  condition:
    any of them
}