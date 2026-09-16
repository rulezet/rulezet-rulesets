rule TTP_XOR_QUAD_CurrentVersionRun_343a {
  strings:
    $key_343a = { 67 55 [2] 43 5b [2] 68 77 [2] 46 55 [2] 52 4e [2] 5d 54 [2] 43 49 [2] 41 48 [2] 5a 4e [2] 46 49 [2] 5a 66 }

  condition:
    any of them
}