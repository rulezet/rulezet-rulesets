rule TTP_XOR_QUAD_CurrentVersionRun_512d {
  strings:
    $key_512d = { 02 42 [2] 26 4c [2] 0d 60 [2] 23 42 [2] 37 59 [2] 38 43 [2] 26 5e [2] 24 5f [2] 3f 59 [2] 23 5e [2] 3f 71 }

  condition:
    any of them
}