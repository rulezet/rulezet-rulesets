rule TTP_XOR_QUAD_CurrentVersionRun_2420 {
  strings:
    $key_2420 = { 77 4f [2] 53 41 [2] 78 6d [2] 56 4f [2] 42 54 [2] 4d 4e [2] 53 53 [2] 51 52 [2] 4a 54 [2] 56 53 [2] 4a 7c }

  condition:
    any of them
}