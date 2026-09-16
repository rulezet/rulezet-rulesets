rule TTP_XOR_QUAD_CurrentVersionRun_593a {
  strings:
    $key_593a = { 0a 55 [2] 2e 5b [2] 05 77 [2] 2b 55 [2] 3f 4e [2] 30 54 [2] 2e 49 [2] 2c 48 [2] 37 4e [2] 2b 49 [2] 37 66 }

  condition:
    any of them
}