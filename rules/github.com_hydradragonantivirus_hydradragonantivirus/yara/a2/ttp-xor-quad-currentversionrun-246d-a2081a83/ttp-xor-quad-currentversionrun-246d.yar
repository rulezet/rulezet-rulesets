rule TTP_XOR_QUAD_CurrentVersionRun_246d {
  strings:
    $key_246d = { 77 02 [2] 53 0c [2] 78 20 [2] 56 02 [2] 42 19 [2] 4d 03 [2] 53 1e [2] 51 1f [2] 4a 19 [2] 56 1e [2] 4a 31 }

  condition:
    any of them
}