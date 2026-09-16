rule TTP_XOR_QUAD_CurrentVersionRun_5520 {
  strings:
    $key_5520 = { 06 4f [2] 22 41 [2] 09 6d [2] 27 4f [2] 33 54 [2] 3c 4e [2] 22 53 [2] 20 52 [2] 3b 54 [2] 27 53 [2] 3b 7c }

  condition:
    any of them
}