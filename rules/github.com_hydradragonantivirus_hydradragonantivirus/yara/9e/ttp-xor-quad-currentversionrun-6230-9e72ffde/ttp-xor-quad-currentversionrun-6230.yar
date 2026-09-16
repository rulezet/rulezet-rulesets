rule TTP_XOR_QUAD_CurrentVersionRun_6230 {
  strings:
    $key_6230 = { 31 5f [2] 15 51 [2] 3e 7d [2] 10 5f [2] 04 44 [2] 0b 5e [2] 15 43 [2] 17 42 [2] 0c 44 [2] 10 43 [2] 0c 6c }

  condition:
    any of them
}