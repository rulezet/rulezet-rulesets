rule TTP_XOR_QUAD_CurrentVersionRun_f9fc {
  strings:
    $key_f9fc = { aa 93 [2] 8e 9d [2] a5 b1 [2] 8b 93 [2] 9f 88 [2] 90 92 [2] 8e 8f [2] 8c 8e [2] 97 88 [2] 8b 8f [2] 97 a0 }

  condition:
    any of them
}