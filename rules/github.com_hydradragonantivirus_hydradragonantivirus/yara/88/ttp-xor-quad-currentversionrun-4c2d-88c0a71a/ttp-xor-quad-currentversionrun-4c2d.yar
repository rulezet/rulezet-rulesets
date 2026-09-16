rule TTP_XOR_QUAD_CurrentVersionRun_4c2d {
  strings:
    $key_4c2d = { 1f 42 [2] 3b 4c [2] 10 60 [2] 3e 42 [2] 2a 59 [2] 25 43 [2] 3b 5e [2] 39 5f [2] 22 59 [2] 3e 5e [2] 22 71 }

  condition:
    any of them
}