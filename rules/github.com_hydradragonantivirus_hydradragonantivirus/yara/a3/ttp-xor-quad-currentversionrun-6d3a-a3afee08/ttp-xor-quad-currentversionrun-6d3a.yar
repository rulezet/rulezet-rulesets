rule TTP_XOR_QUAD_CurrentVersionRun_6d3a {
  strings:
    $key_6d3a = { 3e 55 [2] 1a 5b [2] 31 77 [2] 1f 55 [2] 0b 4e [2] 04 54 [2] 1a 49 [2] 18 48 [2] 03 4e [2] 1f 49 [2] 03 66 }

  condition:
    any of them
}