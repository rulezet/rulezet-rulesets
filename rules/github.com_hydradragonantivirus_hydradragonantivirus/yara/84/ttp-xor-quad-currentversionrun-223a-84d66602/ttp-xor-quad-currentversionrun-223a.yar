rule TTP_XOR_QUAD_CurrentVersionRun_223a {
  strings:
    $key_223a = { 71 55 [2] 55 5b [2] 7e 77 [2] 50 55 [2] 44 4e [2] 4b 54 [2] 55 49 [2] 57 48 [2] 4c 4e [2] 50 49 [2] 4c 66 }

  condition:
    any of them
}