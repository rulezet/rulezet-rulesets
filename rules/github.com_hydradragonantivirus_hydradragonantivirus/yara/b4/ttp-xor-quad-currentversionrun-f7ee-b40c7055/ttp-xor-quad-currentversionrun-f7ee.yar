rule TTP_XOR_QUAD_CurrentVersionRun_f7ee {
  strings:
    $key_f7ee = { a4 81 [2] 80 8f [2] ab a3 [2] 85 81 [2] 91 9a [2] 9e 80 [2] 80 9d [2] 82 9c [2] 99 9a [2] 85 9d [2] 99 b2 }

  condition:
    any of them
}