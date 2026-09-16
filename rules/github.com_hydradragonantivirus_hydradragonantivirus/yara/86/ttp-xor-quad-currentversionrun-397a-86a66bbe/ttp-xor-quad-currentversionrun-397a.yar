rule TTP_XOR_QUAD_CurrentVersionRun_397a {
  strings:
    $key_397a = { 6a 15 [2] 4e 1b [2] 65 37 [2] 4b 15 [2] 5f 0e [2] 50 14 [2] 4e 09 [2] 4c 08 [2] 57 0e [2] 4b 09 [2] 57 26 }

  condition:
    any of them
}