rule TTP_XOR_QUAD_CurrentVersionRun_f94d {
  strings:
    $key_f94d = { aa 22 [2] 8e 2c [2] a5 00 [2] 8b 22 [2] 9f 39 [2] 90 23 [2] 8e 3e [2] 8c 3f [2] 97 39 [2] 8b 3e [2] 97 11 }

  condition:
    any of them
}