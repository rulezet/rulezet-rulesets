rule TTP_XOR_QUAD_CurrentVersionRun_704a {
  strings:
    $key_704a = { 23 25 [2] 07 2b [2] 2c 07 [2] 02 25 [2] 16 3e [2] 19 24 [2] 07 39 [2] 05 38 [2] 1e 3e [2] 02 39 [2] 1e 16 }

  condition:
    any of them
}