rule TTP_XOR_QUAD_CurrentVersionRun_003c {
  strings:
    $key_003c = { 53 53 [2] 77 5d [2] 5c 71 [2] 72 53 [2] 66 48 [2] 69 52 [2] 77 4f [2] 75 4e [2] 6e 48 [2] 72 4f [2] 6e 60 }

  condition:
    any of them
}