rule TTP_XOR_QUAD_CurrentVersionRun_3250 {
  strings:
    $key_3250 = { 61 3f [2] 45 31 [2] 6e 1d [2] 40 3f [2] 54 24 [2] 5b 3e [2] 45 23 [2] 47 22 [2] 5c 24 [2] 40 23 [2] 5c 0c }

  condition:
    any of them
}