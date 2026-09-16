rule TTP_XOR_QUAD_CurrentVersionRun_2e6a {
  strings:
    $key_2e6a = { 7d 05 [2] 59 0b [2] 72 27 [2] 5c 05 [2] 48 1e [2] 47 04 [2] 59 19 [2] 5b 18 [2] 40 1e [2] 5c 19 [2] 40 36 }

  condition:
    any of them
}