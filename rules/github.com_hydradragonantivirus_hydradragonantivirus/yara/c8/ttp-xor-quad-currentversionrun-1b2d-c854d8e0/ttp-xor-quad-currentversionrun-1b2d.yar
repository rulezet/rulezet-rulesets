rule TTP_XOR_QUAD_CurrentVersionRun_1b2d {
  strings:
    $key_1b2d = { 48 42 [2] 6c 4c [2] 47 60 [2] 69 42 [2] 7d 59 [2] 72 43 [2] 6c 5e [2] 6e 5f [2] 75 59 [2] 69 5e [2] 75 71 }

  condition:
    any of them
}