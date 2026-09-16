rule TTP_XOR_QUAD_CurrentVersionRun_027c {
  strings:
    $key_027c = { 51 13 [2] 75 1d [2] 5e 31 [2] 70 13 [2] 64 08 [2] 6b 12 [2] 75 0f [2] 77 0e [2] 6c 08 [2] 70 0f [2] 6c 20 }

  condition:
    any of them
}