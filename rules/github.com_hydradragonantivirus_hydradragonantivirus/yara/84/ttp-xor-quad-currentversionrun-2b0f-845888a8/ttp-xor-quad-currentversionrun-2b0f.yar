rule TTP_XOR_QUAD_CurrentVersionRun_2b0f {
  strings:
    $key_2b0f = { 78 60 [2] 5c 6e [2] 77 42 [2] 59 60 [2] 4d 7b [2] 42 61 [2] 5c 7c [2] 5e 7d [2] 45 7b [2] 59 7c [2] 45 53 }

  condition:
    any of them
}