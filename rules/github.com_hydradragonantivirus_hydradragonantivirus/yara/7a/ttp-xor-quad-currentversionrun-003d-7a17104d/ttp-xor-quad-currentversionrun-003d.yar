rule TTP_XOR_QUAD_CurrentVersionRun_003d {
  strings:
    $key_003d = { 53 52 [2] 77 5c [2] 5c 70 [2] 72 52 [2] 66 49 [2] 69 53 [2] 77 4e [2] 75 4f [2] 6e 49 [2] 72 4e [2] 6e 61 }

  condition:
    any of them
}