rule TTP_XOR_QUAD_CurrentVersionRun_204a {
  strings:
    $key_204a = { 73 25 [2] 57 2b [2] 7c 07 [2] 52 25 [2] 46 3e [2] 49 24 [2] 57 39 [2] 55 38 [2] 4e 3e [2] 52 39 [2] 4e 16 }

  condition:
    any of them
}