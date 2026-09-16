rule TTP_XOR_QUAD_CurrentVersionRun_444a {
  strings:
    $key_444a = { 17 25 [2] 33 2b [2] 18 07 [2] 36 25 [2] 22 3e [2] 2d 24 [2] 33 39 [2] 31 38 [2] 2a 3e [2] 36 39 [2] 2a 16 }

  condition:
    any of them
}