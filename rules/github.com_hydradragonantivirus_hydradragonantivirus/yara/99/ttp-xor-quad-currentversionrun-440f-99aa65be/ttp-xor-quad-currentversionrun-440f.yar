rule TTP_XOR_QUAD_CurrentVersionRun_440f {
  strings:
    $key_440f = { 17 60 [2] 33 6e [2] 18 42 [2] 36 60 [2] 22 7b [2] 2d 61 [2] 33 7c [2] 31 7d [2] 2a 7b [2] 36 7c [2] 2a 53 }

  condition:
    any of them
}