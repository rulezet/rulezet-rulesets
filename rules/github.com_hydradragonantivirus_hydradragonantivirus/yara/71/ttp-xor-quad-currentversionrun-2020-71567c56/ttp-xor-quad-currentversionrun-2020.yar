rule TTP_XOR_QUAD_CurrentVersionRun_2020 {
  strings:
    $key_2020 = { 73 4f [2] 57 41 [2] 7c 6d [2] 52 4f [2] 46 54 [2] 49 4e [2] 57 53 [2] 55 52 [2] 4e 54 [2] 52 53 [2] 4e 7c }

  condition:
    any of them
}