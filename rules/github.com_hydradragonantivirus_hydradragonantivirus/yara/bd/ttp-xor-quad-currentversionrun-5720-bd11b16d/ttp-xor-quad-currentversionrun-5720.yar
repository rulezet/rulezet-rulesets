rule TTP_XOR_QUAD_CurrentVersionRun_5720 {
  strings:
    $key_5720 = { 04 4f [2] 20 41 [2] 0b 6d [2] 25 4f [2] 31 54 [2] 3e 4e [2] 20 53 [2] 22 52 [2] 39 54 [2] 25 53 [2] 39 7c }

  condition:
    any of them
}