rule TTP_XOR_QUAD_CurrentVersionRun_2b0c {
  strings:
    $key_2b0c = { 78 63 [2] 5c 6d [2] 77 41 [2] 59 63 [2] 4d 78 [2] 42 62 [2] 5c 7f [2] 5e 7e [2] 45 78 [2] 59 7f [2] 45 50 }

  condition:
    any of them
}