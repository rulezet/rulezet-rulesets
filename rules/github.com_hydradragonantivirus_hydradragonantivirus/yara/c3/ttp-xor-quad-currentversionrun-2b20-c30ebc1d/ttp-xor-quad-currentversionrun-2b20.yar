rule TTP_XOR_QUAD_CurrentVersionRun_2b20 {
  strings:
    $key_2b20 = { 78 4f [2] 5c 41 [2] 77 6d [2] 59 4f [2] 4d 54 [2] 42 4e [2] 5c 53 [2] 5e 52 [2] 45 54 [2] 59 53 [2] 45 7c }

  condition:
    any of them
}