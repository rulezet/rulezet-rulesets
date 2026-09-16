rule TTP_XOR_QUAD_CurrentVersionRun_e540 {
  strings:
    $key_e540 = { b6 2f [2] 92 21 [2] b9 0d [2] 97 2f [2] 83 34 [2] 8c 2e [2] 92 33 [2] 90 32 [2] 8b 34 [2] 97 33 [2] 8b 1c }

  condition:
    any of them
}