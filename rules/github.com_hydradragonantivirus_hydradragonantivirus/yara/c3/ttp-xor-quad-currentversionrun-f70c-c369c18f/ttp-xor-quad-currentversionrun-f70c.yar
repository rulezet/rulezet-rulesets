rule TTP_XOR_QUAD_CurrentVersionRun_f70c {
  strings:
    $key_f70c = { a4 63 [2] 80 6d [2] ab 41 [2] 85 63 [2] 91 78 [2] 9e 62 [2] 80 7f [2] 82 7e [2] 99 78 [2] 85 7f [2] 99 50 }

  condition:
    any of them
}