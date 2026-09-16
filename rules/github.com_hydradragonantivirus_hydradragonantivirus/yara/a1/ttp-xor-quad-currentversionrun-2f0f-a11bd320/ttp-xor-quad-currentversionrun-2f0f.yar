rule TTP_XOR_QUAD_CurrentVersionRun_2f0f {
  strings:
    $key_2f0f = { 7c 60 [2] 58 6e [2] 73 42 [2] 5d 60 [2] 49 7b [2] 46 61 [2] 58 7c [2] 5a 7d [2] 41 7b [2] 5d 7c [2] 41 53 }

  condition:
    any of them
}