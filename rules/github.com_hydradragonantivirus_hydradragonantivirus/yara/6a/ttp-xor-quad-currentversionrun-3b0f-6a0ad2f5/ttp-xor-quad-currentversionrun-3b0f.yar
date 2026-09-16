rule TTP_XOR_QUAD_CurrentVersionRun_3b0f {
  strings:
    $key_3b0f = { 68 60 [2] 4c 6e [2] 67 42 [2] 49 60 [2] 5d 7b [2] 52 61 [2] 4c 7c [2] 4e 7d [2] 55 7b [2] 49 7c [2] 55 53 }

  condition:
    any of them
}