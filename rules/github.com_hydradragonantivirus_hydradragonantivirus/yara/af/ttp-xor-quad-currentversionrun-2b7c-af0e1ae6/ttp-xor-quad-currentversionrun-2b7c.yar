rule TTP_XOR_QUAD_CurrentVersionRun_2b7c {
  strings:
    $key_2b7c = { 78 13 [2] 5c 1d [2] 77 31 [2] 59 13 [2] 4d 08 [2] 42 12 [2] 5c 0f [2] 5e 0e [2] 45 08 [2] 59 0f [2] 45 20 }

  condition:
    any of them
}