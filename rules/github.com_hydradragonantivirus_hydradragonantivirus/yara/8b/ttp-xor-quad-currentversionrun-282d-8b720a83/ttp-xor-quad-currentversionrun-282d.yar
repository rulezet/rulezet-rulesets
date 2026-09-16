rule TTP_XOR_QUAD_CurrentVersionRun_282d {
  strings:
    $key_282d = { 7b 42 [2] 5f 4c [2] 74 60 [2] 5a 42 [2] 4e 59 [2] 41 43 [2] 5f 5e [2] 5d 5f [2] 46 59 [2] 5a 5e [2] 46 71 }

  condition:
    any of them
}