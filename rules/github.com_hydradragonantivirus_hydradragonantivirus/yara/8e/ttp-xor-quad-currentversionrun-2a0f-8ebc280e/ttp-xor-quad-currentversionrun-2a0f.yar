rule TTP_XOR_QUAD_CurrentVersionRun_2a0f {
  strings:
    $key_2a0f = { 79 60 [2] 5d 6e [2] 76 42 [2] 58 60 [2] 4c 7b [2] 43 61 [2] 5d 7c [2] 5f 7d [2] 44 7b [2] 58 7c [2] 44 53 }

  condition:
    any of them
}