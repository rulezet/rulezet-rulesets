rule TTP_XOR_QUAD_CurrentVersionRun_6b3a {
  strings:
    $key_6b3a = { 38 55 [2] 1c 5b [2] 37 77 [2] 19 55 [2] 0d 4e [2] 02 54 [2] 1c 49 [2] 1e 48 [2] 05 4e [2] 19 49 [2] 05 66 }

  condition:
    any of them
}