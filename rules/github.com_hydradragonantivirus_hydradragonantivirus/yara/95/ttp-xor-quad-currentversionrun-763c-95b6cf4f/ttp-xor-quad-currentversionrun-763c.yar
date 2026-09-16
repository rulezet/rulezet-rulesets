rule TTP_XOR_QUAD_CurrentVersionRun_763c {
  strings:
    $key_763c = { 25 53 [2] 01 5d [2] 2a 71 [2] 04 53 [2] 10 48 [2] 1f 52 [2] 01 4f [2] 03 4e [2] 18 48 [2] 04 4f [2] 18 60 }

  condition:
    any of them
}