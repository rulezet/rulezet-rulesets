rule TTP_XOR_QUAD_CurrentVersionRun_d97e {
  strings:
    $key_d97e = { 8a 11 [2] ae 1f [2] 85 33 [2] ab 11 [2] bf 0a [2] b0 10 [2] ae 0d [2] ac 0c [2] b7 0a [2] ab 0d [2] b7 22 }

  condition:
    any of them
}