rule TTP_XOR_QUAD_CurrentVersionRun_196d {
  strings:
    $key_196d = { 4a 02 [2] 6e 0c [2] 45 20 [2] 6b 02 [2] 7f 19 [2] 70 03 [2] 6e 1e [2] 6c 1f [2] 77 19 [2] 6b 1e [2] 77 31 }

  condition:
    any of them
}