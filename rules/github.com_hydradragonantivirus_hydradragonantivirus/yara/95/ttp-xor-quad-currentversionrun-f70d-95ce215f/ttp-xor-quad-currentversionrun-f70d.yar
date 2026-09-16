rule TTP_XOR_QUAD_CurrentVersionRun_f70d {
  strings:
    $key_f70d = { a4 62 [2] 80 6c [2] ab 40 [2] 85 62 [2] 91 79 [2] 9e 63 [2] 80 7e [2] 82 7f [2] 99 79 [2] 85 7e [2] 99 51 }

  condition:
    any of them
}