rule TTP_XOR_QUAD_CurrentVersionRun_f950 {
  strings:
    $key_f950 = { aa 3f [2] 8e 31 [2] a5 1d [2] 8b 3f [2] 9f 24 [2] 90 3e [2] 8e 23 [2] 8c 22 [2] 97 24 [2] 8b 23 [2] 97 0c }

  condition:
    any of them
}