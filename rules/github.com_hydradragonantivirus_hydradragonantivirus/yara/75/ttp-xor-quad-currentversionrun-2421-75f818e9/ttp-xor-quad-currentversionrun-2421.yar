rule TTP_XOR_QUAD_CurrentVersionRun_2421 {
  strings:
    $key_2421 = { 77 4e [2] 53 40 [2] 78 6c [2] 56 4e [2] 42 55 [2] 4d 4f [2] 53 52 [2] 51 53 [2] 4a 55 [2] 56 52 [2] 4a 7d }

  condition:
    any of them
}