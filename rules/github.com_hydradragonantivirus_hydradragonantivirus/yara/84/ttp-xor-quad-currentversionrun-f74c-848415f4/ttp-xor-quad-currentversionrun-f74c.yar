rule TTP_XOR_QUAD_CurrentVersionRun_f74c {
  strings:
    $key_f74c = { a4 23 [2] 80 2d [2] ab 01 [2] 85 23 [2] 91 38 [2] 9e 22 [2] 80 3f [2] 82 3e [2] 99 38 [2] 85 3f [2] 99 10 }

  condition:
    any of them
}