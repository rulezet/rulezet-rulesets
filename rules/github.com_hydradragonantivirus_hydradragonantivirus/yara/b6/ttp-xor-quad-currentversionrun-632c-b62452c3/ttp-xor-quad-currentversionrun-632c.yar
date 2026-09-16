rule TTP_XOR_QUAD_CurrentVersionRun_632c {
  strings:
    $key_632c = { 30 43 [2] 14 4d [2] 3f 61 [2] 11 43 [2] 05 58 [2] 0a 42 [2] 14 5f [2] 16 5e [2] 0d 58 [2] 11 5f [2] 0d 70 }

  condition:
    any of them
}