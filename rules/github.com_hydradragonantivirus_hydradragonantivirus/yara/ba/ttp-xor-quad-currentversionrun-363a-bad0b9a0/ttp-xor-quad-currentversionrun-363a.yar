rule TTP_XOR_QUAD_CurrentVersionRun_363a {
  strings:
    $key_363a = { 65 55 [2] 41 5b [2] 6a 77 [2] 44 55 [2] 50 4e [2] 5f 54 [2] 41 49 [2] 43 48 [2] 58 4e [2] 44 49 [2] 58 66 }

  condition:
    any of them
}