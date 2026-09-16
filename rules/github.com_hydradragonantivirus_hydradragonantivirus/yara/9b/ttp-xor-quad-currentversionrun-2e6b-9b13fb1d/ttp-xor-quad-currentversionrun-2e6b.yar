rule TTP_XOR_QUAD_CurrentVersionRun_2e6b {
  strings:
    $key_2e6b = { 7d 04 [2] 59 0a [2] 72 26 [2] 5c 04 [2] 48 1f [2] 47 05 [2] 59 18 [2] 5b 19 [2] 40 1f [2] 5c 18 [2] 40 37 }

  condition:
    any of them
}