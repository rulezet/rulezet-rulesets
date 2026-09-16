rule TTP_XOR_QUAD_CurrentVersionRun_6d30 {
  strings:
    $key_6d30 = { 3e 5f [2] 1a 51 [2] 31 7d [2] 1f 5f [2] 0b 44 [2] 04 5e [2] 1a 43 [2] 18 42 [2] 03 44 [2] 1f 43 [2] 03 6c }

  condition:
    any of them
}