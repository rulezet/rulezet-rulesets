rule TTP_XOR_QUAD_CurrentVersionRun_0c2d {
  strings:
    $key_0c2d = { 5f 42 [2] 7b 4c [2] 50 60 [2] 7e 42 [2] 6a 59 [2] 65 43 [2] 7b 5e [2] 79 5f [2] 62 59 [2] 7e 5e [2] 62 71 }

  condition:
    any of them
}