rule TTP_XOR_QUAD_CurrentVersionRun_f21e {
  strings:
    $key_f21e = { a1 71 [2] 85 7f [2] ae 53 [2] 80 71 [2] 94 6a [2] 9b 70 [2] 85 6d [2] 87 6c [2] 9c 6a [2] 80 6d [2] 9c 42 }

  condition:
    any of them
}