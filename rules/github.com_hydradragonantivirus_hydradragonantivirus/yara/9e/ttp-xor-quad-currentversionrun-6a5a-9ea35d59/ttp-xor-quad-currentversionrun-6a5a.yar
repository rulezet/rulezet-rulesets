rule TTP_XOR_QUAD_CurrentVersionRun_6a5a {
  strings:
    $key_6a5a = { 39 35 [2] 1d 3b [2] 36 17 [2] 18 35 [2] 0c 2e [2] 03 34 [2] 1d 29 [2] 1f 28 [2] 04 2e [2] 18 29 [2] 04 06 }

  condition:
    any of them
}