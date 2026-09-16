rule TTP_XOR_QUAD_CurrentVersionRun_f9ed {
  strings:
    $key_f9ed = { aa 82 [2] 8e 8c [2] a5 a0 [2] 8b 82 [2] 9f 99 [2] 90 83 [2] 8e 9e [2] 8c 9f [2] 97 99 [2] 8b 9e [2] 97 b1 }

  condition:
    any of them
}