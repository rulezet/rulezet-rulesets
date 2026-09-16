rule TTP_XOR_QUAD_CurrentVersionRun_ffed {
  strings:
    $key_ffed = { ac 82 [2] 88 8c [2] a3 a0 [2] 8d 82 [2] 99 99 [2] 96 83 [2] 88 9e [2] 8a 9f [2] 91 99 [2] 8d 9e [2] 91 b1 }

  condition:
    any of them
}