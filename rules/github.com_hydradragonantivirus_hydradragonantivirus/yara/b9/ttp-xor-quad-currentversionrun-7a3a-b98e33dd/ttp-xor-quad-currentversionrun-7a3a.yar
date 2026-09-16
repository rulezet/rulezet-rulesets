rule TTP_XOR_QUAD_CurrentVersionRun_7a3a {
  strings:
    $key_7a3a = { 29 55 [2] 0d 5b [2] 26 77 [2] 08 55 [2] 1c 4e [2] 13 54 [2] 0d 49 [2] 0f 48 [2] 14 4e [2] 08 49 [2] 14 66 }

  condition:
    any of them
}