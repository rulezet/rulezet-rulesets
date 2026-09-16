rule TTP_XOR_QUAD_CurrentVersionRun_242c {
  strings:
    $key_242c = { 77 43 [2] 53 4d [2] 78 61 [2] 56 43 [2] 42 58 [2] 4d 42 [2] 53 5f [2] 51 5e [2] 4a 58 [2] 56 5f [2] 4a 70 }

  condition:
    any of them
}