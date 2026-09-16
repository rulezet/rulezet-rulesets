rule TTP_XOR_QUAD_CurrentVersionRun_403d {
  strings:
    $key_403d = { 13 52 [2] 37 5c [2] 1c 70 [2] 32 52 [2] 26 49 [2] 29 53 [2] 37 4e [2] 35 4f [2] 2e 49 [2] 32 4e [2] 2e 61 }

  condition:
    any of them
}