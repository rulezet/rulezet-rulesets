rule TTP_XOR_QUAD_CurrentVersionRun_7020 {
  strings:
    $key_7020 = { 23 4f [2] 07 41 [2] 2c 6d [2] 02 4f [2] 16 54 [2] 19 4e [2] 07 53 [2] 05 52 [2] 1e 54 [2] 02 53 [2] 1e 7c }

  condition:
    any of them
}