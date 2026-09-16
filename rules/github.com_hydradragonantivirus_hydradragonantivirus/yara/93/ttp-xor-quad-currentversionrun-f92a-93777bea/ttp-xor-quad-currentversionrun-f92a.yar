rule TTP_XOR_QUAD_CurrentVersionRun_f92a {
  strings:
    $key_f92a = { aa 45 [2] 8e 4b [2] a5 67 [2] 8b 45 [2] 9f 5e [2] 90 44 [2] 8e 59 [2] 8c 58 [2] 97 5e [2] 8b 59 [2] 97 76 }

  condition:
    any of them
}