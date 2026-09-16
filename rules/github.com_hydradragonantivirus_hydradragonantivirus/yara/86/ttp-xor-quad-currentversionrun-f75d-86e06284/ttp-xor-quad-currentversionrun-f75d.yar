rule TTP_XOR_QUAD_CurrentVersionRun_f75d {
  strings:
    $key_f75d = { a4 32 [2] 80 3c [2] ab 10 [2] 85 32 [2] 91 29 [2] 9e 33 [2] 80 2e [2] 82 2f [2] 99 29 [2] 85 2e [2] 99 01 }

  condition:
    any of them
}