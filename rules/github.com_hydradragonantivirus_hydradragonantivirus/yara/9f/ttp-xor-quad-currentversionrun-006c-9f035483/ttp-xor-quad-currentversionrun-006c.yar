rule TTP_XOR_QUAD_CurrentVersionRun_006c {
  strings:
    $key_006c = { 53 03 [2] 77 0d [2] 5c 21 [2] 72 03 [2] 66 18 [2] 69 02 [2] 77 1f [2] 75 1e [2] 6e 18 [2] 72 1f [2] 6e 30 }

  condition:
    any of them
}