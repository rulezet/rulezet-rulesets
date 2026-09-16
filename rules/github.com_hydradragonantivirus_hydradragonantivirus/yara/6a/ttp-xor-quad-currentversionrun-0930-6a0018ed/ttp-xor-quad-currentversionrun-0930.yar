rule TTP_XOR_QUAD_CurrentVersionRun_0930 {
  strings:
    $key_0930 = { 5a 5f [2] 7e 51 [2] 55 7d [2] 7b 5f [2] 6f 44 [2] 60 5e [2] 7e 43 [2] 7c 42 [2] 67 44 [2] 7b 43 [2] 67 6c }

  condition:
    any of them
}