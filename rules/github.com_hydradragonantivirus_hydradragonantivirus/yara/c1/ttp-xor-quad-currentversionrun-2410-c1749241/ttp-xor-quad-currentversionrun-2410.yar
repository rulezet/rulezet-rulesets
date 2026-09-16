rule TTP_XOR_QUAD_CurrentVersionRun_2410 {
  strings:
    $key_2410 = { 77 7f [2] 53 71 [2] 78 5d [2] 56 7f [2] 42 64 [2] 4d 7e [2] 53 63 [2] 51 62 [2] 4a 64 [2] 56 63 [2] 4a 4c }

  condition:
    any of them
}