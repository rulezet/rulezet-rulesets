rule TTP_XOR_QUAD_CurrentVersionRun_3a4a {
  strings:
    $key_3a4a = { 69 25 [2] 4d 2b [2] 66 07 [2] 48 25 [2] 5c 3e [2] 53 24 [2] 4d 39 [2] 4f 38 [2] 54 3e [2] 48 39 [2] 54 16 }

  condition:
    any of them
}