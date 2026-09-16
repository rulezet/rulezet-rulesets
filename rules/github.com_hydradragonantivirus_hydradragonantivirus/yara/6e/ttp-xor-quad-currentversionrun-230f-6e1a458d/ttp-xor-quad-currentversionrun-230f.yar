rule TTP_XOR_QUAD_CurrentVersionRun_230f {
  strings:
    $key_230f = { 70 60 [2] 54 6e [2] 7f 42 [2] 51 60 [2] 45 7b [2] 4a 61 [2] 54 7c [2] 56 7d [2] 4d 7b [2] 51 7c [2] 4d 53 }

  condition:
    any of them
}