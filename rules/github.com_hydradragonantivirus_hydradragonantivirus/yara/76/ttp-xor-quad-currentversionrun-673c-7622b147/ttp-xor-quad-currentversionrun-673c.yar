rule TTP_XOR_QUAD_CurrentVersionRun_673c {
  strings:
    $key_673c = { 34 53 [2] 10 5d [2] 3b 71 [2] 15 53 [2] 01 48 [2] 0e 52 [2] 10 4f [2] 12 4e [2] 09 48 [2] 15 4f [2] 09 60 }

  condition:
    any of them
}