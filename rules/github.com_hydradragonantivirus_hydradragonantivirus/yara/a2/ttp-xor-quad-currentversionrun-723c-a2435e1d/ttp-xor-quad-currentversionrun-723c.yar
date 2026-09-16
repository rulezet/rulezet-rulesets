rule TTP_XOR_QUAD_CurrentVersionRun_723c {
  strings:
    $key_723c = { 21 53 [2] 05 5d [2] 2e 71 [2] 00 53 [2] 14 48 [2] 1b 52 [2] 05 4f [2] 07 4e [2] 1c 48 [2] 00 4f [2] 1c 60 }

  condition:
    any of them
}