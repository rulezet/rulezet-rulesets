rule TTP_XOR_QUAD_CurrentVersionRun_0d50 {
  strings:
    $key_0d50 = { 5e 3f [2] 7a 31 [2] 51 1d [2] 7f 3f [2] 6b 24 [2] 64 3e [2] 7a 23 [2] 78 22 [2] 63 24 [2] 7f 23 [2] 63 0c }

  condition:
    any of them
}