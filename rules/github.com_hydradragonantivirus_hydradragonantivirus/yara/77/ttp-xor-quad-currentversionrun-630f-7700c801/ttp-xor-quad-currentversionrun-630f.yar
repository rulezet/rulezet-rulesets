rule TTP_XOR_QUAD_CurrentVersionRun_630f {
  strings:
    $key_630f = { 30 60 [2] 14 6e [2] 3f 42 [2] 11 60 [2] 05 7b [2] 0a 61 [2] 14 7c [2] 16 7d [2] 0d 7b [2] 11 7c [2] 0d 53 }

  condition:
    any of them
}