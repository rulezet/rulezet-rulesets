rule TTP_XOR_QUAD_CurrentVersionRun_027a {
  strings:
    $key_027a = { 51 15 [2] 75 1b [2] 5e 37 [2] 70 15 [2] 64 0e [2] 6b 14 [2] 75 09 [2] 77 08 [2] 6c 0e [2] 70 09 [2] 6c 26 }

  condition:
    any of them
}