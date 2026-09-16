rule TTP_XOR_QUAD_CurrentVersionRun_f72c {
  strings:
    $key_f72c = { a4 43 [2] 80 4d [2] ab 61 [2] 85 43 [2] 91 58 [2] 9e 42 [2] 80 5f [2] 82 5e [2] 99 58 [2] 85 5f [2] 99 70 }

  condition:
    any of them
}