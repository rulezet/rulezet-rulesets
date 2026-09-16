rule TTP_XOR_QUAD_CurrentVersionRun_3c40 {
  strings:
    $key_3c40 = { 6f 2f [2] 4b 21 [2] 60 0d [2] 4e 2f [2] 5a 34 [2] 55 2e [2] 4b 33 [2] 49 32 [2] 52 34 [2] 4e 33 [2] 52 1c }

  condition:
    any of them
}