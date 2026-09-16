rule TTP_XOR_QUAD_CurrentVersionRun_4b2d {
  strings:
    $key_4b2d = { 18 42 [2] 3c 4c [2] 17 60 [2] 39 42 [2] 2d 59 [2] 22 43 [2] 3c 5e [2] 3e 5f [2] 25 59 [2] 39 5e [2] 25 71 }

  condition:
    any of them
}