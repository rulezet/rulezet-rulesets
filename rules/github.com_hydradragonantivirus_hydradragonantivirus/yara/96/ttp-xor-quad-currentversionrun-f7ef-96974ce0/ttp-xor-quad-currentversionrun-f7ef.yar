rule TTP_XOR_QUAD_CurrentVersionRun_f7ef {
  strings:
    $key_f7ef = { a4 80 [2] 80 8e [2] ab a2 [2] 85 80 [2] 91 9b [2] 9e 81 [2] 80 9c [2] 82 9d [2] 99 9b [2] 85 9c [2] 99 b3 }

  condition:
    any of them
}