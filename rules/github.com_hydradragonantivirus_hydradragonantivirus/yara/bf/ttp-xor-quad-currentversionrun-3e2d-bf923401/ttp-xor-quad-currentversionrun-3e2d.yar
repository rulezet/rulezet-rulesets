rule TTP_XOR_QUAD_CurrentVersionRun_3e2d {
  strings:
    $key_3e2d = { 6d 42 [2] 49 4c [2] 62 60 [2] 4c 42 [2] 58 59 [2] 57 43 [2] 49 5e [2] 4b 5f [2] 50 59 [2] 4c 5e [2] 50 71 }

  condition:
    any of them
}