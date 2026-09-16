rule TTP_XOR_QUAD_CurrentVersionRun_396a {
  strings:
    $key_396a = { 6a 05 [2] 4e 0b [2] 65 27 [2] 4b 05 [2] 5f 1e [2] 50 04 [2] 4e 19 [2] 4c 18 [2] 57 1e [2] 4b 19 [2] 57 36 }

  condition:
    any of them
}