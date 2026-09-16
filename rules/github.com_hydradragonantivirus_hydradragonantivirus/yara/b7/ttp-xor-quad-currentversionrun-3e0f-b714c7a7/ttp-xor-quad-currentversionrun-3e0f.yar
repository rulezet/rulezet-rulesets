rule TTP_XOR_QUAD_CurrentVersionRun_3e0f {
  strings:
    $key_3e0f = { 6d 60 [2] 49 6e [2] 62 42 [2] 4c 60 [2] 58 7b [2] 57 61 [2] 49 7c [2] 4b 7d [2] 50 7b [2] 4c 7c [2] 50 53 }

  condition:
    any of them
}