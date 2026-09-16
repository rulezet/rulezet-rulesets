rule TTP_XOR_QUAD_CurrentVersionRun_f7eb {
  strings:
    $key_f7eb = { a4 84 [2] 80 8a [2] ab a6 [2] 85 84 [2] 91 9f [2] 9e 85 [2] 80 98 [2] 82 99 [2] 99 9f [2] 85 98 [2] 99 b7 }

  condition:
    any of them
}