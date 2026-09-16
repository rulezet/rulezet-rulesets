rule TTP_XOR_QUAD_CurrentVersionRun_f92d {
  strings:
    $key_f92d = { aa 42 [2] 8e 4c [2] a5 60 [2] 8b 42 [2] 9f 59 [2] 90 43 [2] 8e 5e [2] 8c 5f [2] 97 59 [2] 8b 5e [2] 97 71 }

  condition:
    any of them
}