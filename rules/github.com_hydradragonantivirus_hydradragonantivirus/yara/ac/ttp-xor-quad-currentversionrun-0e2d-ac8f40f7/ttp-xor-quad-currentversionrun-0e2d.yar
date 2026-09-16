rule TTP_XOR_QUAD_CurrentVersionRun_0e2d {
  strings:
    $key_0e2d = { 5d 42 [2] 79 4c [2] 52 60 [2] 7c 42 [2] 68 59 [2] 67 43 [2] 79 5e [2] 7b 5f [2] 60 59 [2] 7c 5e [2] 60 71 }

  condition:
    any of them
}