rule TTP_XOR_QUAD_CurrentVersionRun_352d {
  strings:
    $key_352d = { 66 42 [2] 42 4c [2] 69 60 [2] 47 42 [2] 53 59 [2] 5c 43 [2] 42 5e [2] 40 5f [2] 5b 59 [2] 47 5e [2] 5b 71 }

  condition:
    any of them
}