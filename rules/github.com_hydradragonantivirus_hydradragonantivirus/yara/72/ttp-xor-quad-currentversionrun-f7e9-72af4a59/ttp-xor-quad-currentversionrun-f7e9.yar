rule TTP_XOR_QUAD_CurrentVersionRun_f7e9 {
  strings:
    $key_f7e9 = { a4 86 [2] 80 88 [2] ab a4 [2] 85 86 [2] 91 9d [2] 9e 87 [2] 80 9a [2] 82 9b [2] 99 9d [2] 85 9a [2] 99 b5 }

  condition:
    any of them
}