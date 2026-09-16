rule TTP_XOR_QUAD_CurrentVersionRun_4b4a {
  strings:
    $key_4b4a = { 18 25 [2] 3c 2b [2] 17 07 [2] 39 25 [2] 2d 3e [2] 22 24 [2] 3c 39 [2] 3e 38 [2] 25 3e [2] 39 39 [2] 25 16 }

  condition:
    any of them
}