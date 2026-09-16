rule TTP_XOR_QUAD_CurrentVersionRun_693c {
  strings:
    $key_693c = { 3a 53 [2] 1e 5d [2] 35 71 [2] 1b 53 [2] 0f 48 [2] 00 52 [2] 1e 4f [2] 1c 4e [2] 07 48 [2] 1b 4f [2] 07 60 }

  condition:
    any of them
}