rule TTP_XOR_QUAD_CurrentVersionRun_3520 {
  strings:
    $key_3520 = { 66 4f [2] 42 41 [2] 69 6d [2] 47 4f [2] 53 54 [2] 5c 4e [2] 42 53 [2] 40 52 [2] 5b 54 [2] 47 53 [2] 5b 7c }

  condition:
    any of them
}