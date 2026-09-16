rule TTP_XOR_QUAD_CurrentVersionRun_2b10 {
  strings:
    $key_2b10 = { 78 7f [2] 5c 71 [2] 77 5d [2] 59 7f [2] 4d 64 [2] 42 7e [2] 5c 63 [2] 5e 62 [2] 45 64 [2] 59 63 [2] 45 4c }

  condition:
    any of them
}