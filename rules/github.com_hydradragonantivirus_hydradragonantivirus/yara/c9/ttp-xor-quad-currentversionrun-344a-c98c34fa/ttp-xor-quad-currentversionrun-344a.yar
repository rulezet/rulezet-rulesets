rule TTP_XOR_QUAD_CurrentVersionRun_344a {
  strings:
    $key_344a = { 67 25 [2] 43 2b [2] 68 07 [2] 46 25 [2] 52 3e [2] 5d 24 [2] 43 39 [2] 41 38 [2] 5a 3e [2] 46 39 [2] 5a 16 }

  condition:
    any of them
}