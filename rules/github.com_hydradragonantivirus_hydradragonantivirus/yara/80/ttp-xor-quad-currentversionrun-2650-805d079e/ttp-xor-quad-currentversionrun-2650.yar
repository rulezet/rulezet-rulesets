rule TTP_XOR_QUAD_CurrentVersionRun_2650 {
  strings:
    $key_2650 = { 75 3f [2] 51 31 [2] 7a 1d [2] 54 3f [2] 40 24 [2] 4f 3e [2] 51 23 [2] 53 22 [2] 48 24 [2] 54 23 [2] 48 0c }

  condition:
    any of them
}