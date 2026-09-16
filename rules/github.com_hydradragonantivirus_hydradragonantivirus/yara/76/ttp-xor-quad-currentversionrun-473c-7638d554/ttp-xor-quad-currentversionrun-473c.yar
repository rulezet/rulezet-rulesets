rule TTP_XOR_QUAD_CurrentVersionRun_473c {
  strings:
    $key_473c = { 14 53 [2] 30 5d [2] 1b 71 [2] 35 53 [2] 21 48 [2] 2e 52 [2] 30 4f [2] 32 4e [2] 29 48 [2] 35 4f [2] 29 60 }

  condition:
    any of them
}