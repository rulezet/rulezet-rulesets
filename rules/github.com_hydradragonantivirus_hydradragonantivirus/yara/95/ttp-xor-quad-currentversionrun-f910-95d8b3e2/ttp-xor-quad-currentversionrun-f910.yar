rule TTP_XOR_QUAD_CurrentVersionRun_f910 {
  strings:
    $key_f910 = { aa 7f [2] 8e 71 [2] a5 5d [2] 8b 7f [2] 9f 64 [2] 90 7e [2] 8e 63 [2] 8c 62 [2] 97 64 [2] 8b 63 [2] 97 4c }

  condition:
    any of them
}