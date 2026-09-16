rule TTP_XOR_QUAD_CurrentVersionRun_333a {
  strings:
    $key_333a = { 60 55 [2] 44 5b [2] 6f 77 [2] 41 55 [2] 55 4e [2] 5a 54 [2] 44 49 [2] 46 48 [2] 5d 4e [2] 41 49 [2] 5d 66 }

  condition:
    any of them
}