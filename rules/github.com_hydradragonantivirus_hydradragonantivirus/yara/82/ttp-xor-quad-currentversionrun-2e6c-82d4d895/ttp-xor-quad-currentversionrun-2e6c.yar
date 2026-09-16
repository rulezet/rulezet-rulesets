rule TTP_XOR_QUAD_CurrentVersionRun_2e6c {
  strings:
    $key_2e6c = { 7d 03 [2] 59 0d [2] 72 21 [2] 5c 03 [2] 48 18 [2] 47 02 [2] 59 1f [2] 5b 1e [2] 40 18 [2] 5c 1f [2] 40 30 }

  condition:
    any of them
}