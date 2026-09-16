rule TTP_XOR_QUAD_CurrentVersionRun_180f {
  strings:
    $key_180f = { 4b 60 [2] 6f 6e [2] 44 42 [2] 6a 60 [2] 7e 7b [2] 71 61 [2] 6f 7c [2] 6d 7d [2] 76 7b [2] 6a 7c [2] 76 53 }

  condition:
    any of them
}