rule TTP_XOR_QUAD_CurrentVersionRun_f7fc {
  strings:
    $key_f7fc = { a4 93 [2] 80 9d [2] ab b1 [2] 85 93 [2] 91 88 [2] 9e 92 [2] 80 8f [2] 82 8e [2] 99 88 [2] 85 8f [2] 99 a0 }

  condition:
    any of them
}