rule TTP_XOR_QUAD_CurrentVersionRun_2e2d {
  strings:
    $key_2e2d = { 7d 42 [2] 59 4c [2] 72 60 [2] 5c 42 [2] 48 59 [2] 47 43 [2] 59 5e [2] 5b 5f [2] 40 59 [2] 5c 5e [2] 40 71 }

  condition:
    any of them
}