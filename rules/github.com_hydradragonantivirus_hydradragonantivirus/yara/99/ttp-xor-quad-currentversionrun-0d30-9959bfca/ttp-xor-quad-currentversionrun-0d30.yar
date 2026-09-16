rule TTP_XOR_QUAD_CurrentVersionRun_0d30 {
  strings:
    $key_0d30 = { 5e 5f [2] 7a 51 [2] 51 7d [2] 7f 5f [2] 6b 44 [2] 64 5e [2] 7a 43 [2] 78 42 [2] 63 44 [2] 7f 43 [2] 63 6c }

  condition:
    any of them
}