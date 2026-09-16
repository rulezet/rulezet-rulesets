rule TTP_XOR_QUAD_CurrentVersionRun_030f {
  strings:
    $key_030f = { 50 60 [2] 74 6e [2] 5f 42 [2] 71 60 [2] 65 7b [2] 6a 61 [2] 74 7c [2] 76 7d [2] 6d 7b [2] 71 7c [2] 6d 53 }

  condition:
    any of them
}