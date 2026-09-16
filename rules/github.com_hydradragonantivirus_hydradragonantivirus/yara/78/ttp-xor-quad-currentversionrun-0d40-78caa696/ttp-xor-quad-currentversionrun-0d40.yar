rule TTP_XOR_QUAD_CurrentVersionRun_0d40 {
  strings:
    $key_0d40 = { 5e 2f [2] 7a 21 [2] 51 0d [2] 7f 2f [2] 6b 34 [2] 64 2e [2] 7a 33 [2] 78 32 [2] 63 34 [2] 7f 33 [2] 63 1c }

  condition:
    any of them
}