rule TTP_XOR_QUAD_CurrentVersionRun_e630 {
  strings:
    $key_e630 = { b5 5f [2] 91 51 [2] ba 7d [2] 94 5f [2] 80 44 [2] 8f 5e [2] 91 43 [2] 93 42 [2] 88 44 [2] 94 43 [2] 88 6c }

  condition:
    any of them
}