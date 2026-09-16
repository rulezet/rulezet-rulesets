rule TTP_XOR_QUAD_CurrentVersionRun_f94c {
  strings:
    $key_f94c = { aa 23 [2] 8e 2d [2] a5 01 [2] 8b 23 [2] 9f 38 [2] 90 22 [2] 8e 3f [2] 8c 3e [2] 97 38 [2] 8b 3f [2] 97 10 }

  condition:
    any of them
}