rule TTP_XOR_QUAD_CurrentVersionRun_1910 {
  strings:
    $key_1910 = { 4a 7f [2] 6e 71 [2] 45 5d [2] 6b 7f [2] 7f 64 [2] 70 7e [2] 6e 63 [2] 6c 62 [2] 77 64 [2] 6b 63 [2] 77 4c }

  condition:
    any of them
}