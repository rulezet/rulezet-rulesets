rule TTP_XOR_QUAD_CurrentVersionRun_4b3a {
  strings:
    $key_4b3a = { 18 55 [2] 3c 5b [2] 17 77 [2] 39 55 [2] 2d 4e [2] 22 54 [2] 3c 49 [2] 3e 48 [2] 25 4e [2] 39 49 [2] 25 66 }

  condition:
    any of them
}