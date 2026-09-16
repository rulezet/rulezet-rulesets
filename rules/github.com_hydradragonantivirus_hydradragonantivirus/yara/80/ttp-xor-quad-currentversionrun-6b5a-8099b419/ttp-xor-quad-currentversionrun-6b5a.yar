rule TTP_XOR_QUAD_CurrentVersionRun_6b5a {
  strings:
    $key_6b5a = { 38 35 [2] 1c 3b [2] 37 17 [2] 19 35 [2] 0d 2e [2] 02 34 [2] 1c 29 [2] 1e 28 [2] 05 2e [2] 19 29 [2] 05 06 }

  condition:
    any of them
}