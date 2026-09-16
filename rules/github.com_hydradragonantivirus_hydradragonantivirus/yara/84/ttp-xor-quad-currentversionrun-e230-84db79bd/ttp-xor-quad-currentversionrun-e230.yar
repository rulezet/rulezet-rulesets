rule TTP_XOR_QUAD_CurrentVersionRun_e230 {
  strings:
    $key_e230 = { b1 5f [2] 95 51 [2] be 7d [2] 90 5f [2] 84 44 [2] 8b 5e [2] 95 43 [2] 97 42 [2] 8c 44 [2] 90 43 [2] 8c 6c }

  condition:
    any of them
}