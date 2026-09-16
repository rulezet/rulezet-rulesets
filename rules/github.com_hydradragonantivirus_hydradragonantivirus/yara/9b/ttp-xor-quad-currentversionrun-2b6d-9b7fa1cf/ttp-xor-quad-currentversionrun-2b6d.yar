rule TTP_XOR_QUAD_CurrentVersionRun_2b6d {
  strings:
    $key_2b6d = { 78 02 [2] 5c 0c [2] 77 20 [2] 59 02 [2] 4d 19 [2] 42 03 [2] 5c 1e [2] 5e 1f [2] 45 19 [2] 59 1e [2] 45 31 }

  condition:
    any of them
}