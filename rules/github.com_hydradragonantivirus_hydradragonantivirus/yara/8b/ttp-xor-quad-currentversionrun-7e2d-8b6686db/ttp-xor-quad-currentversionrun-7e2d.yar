rule TTP_XOR_QUAD_CurrentVersionRun_7e2d {
  strings:
    $key_7e2d = { 2d 42 [2] 09 4c [2] 22 60 [2] 0c 42 [2] 18 59 [2] 17 43 [2] 09 5e [2] 0b 5f [2] 10 59 [2] 0c 5e [2] 10 71 }

  condition:
    any of them
}