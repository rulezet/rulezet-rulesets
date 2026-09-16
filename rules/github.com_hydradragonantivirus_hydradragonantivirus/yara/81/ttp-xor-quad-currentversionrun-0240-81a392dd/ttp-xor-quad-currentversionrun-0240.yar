rule TTP_XOR_QUAD_CurrentVersionRun_0240 {
  strings:
    $key_0240 = { 51 2f [2] 75 21 [2] 5e 0d [2] 70 2f [2] 64 34 [2] 6b 2e [2] 75 33 [2] 77 32 [2] 6c 34 [2] 70 33 [2] 6c 1c }

  condition:
    any of them
}