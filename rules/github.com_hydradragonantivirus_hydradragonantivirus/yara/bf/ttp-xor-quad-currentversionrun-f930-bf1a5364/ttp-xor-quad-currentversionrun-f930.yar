rule TTP_XOR_QUAD_CurrentVersionRun_f930 {
  strings:
    $key_f930 = { aa 5f [2] 8e 51 [2] a5 7d [2] 8b 5f [2] 9f 44 [2] 90 5e [2] 8e 43 [2] 8c 42 [2] 97 44 [2] 8b 43 [2] 97 6c }

  condition:
    any of them
}