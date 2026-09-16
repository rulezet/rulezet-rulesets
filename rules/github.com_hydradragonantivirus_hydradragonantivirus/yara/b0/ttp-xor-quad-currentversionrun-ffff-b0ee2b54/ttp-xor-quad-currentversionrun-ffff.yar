rule TTP_XOR_QUAD_CurrentVersionRun_ffff {
  strings:
    $key_ffff = { ac 90 [2] 88 9e [2] a3 b2 [2] 8d 90 [2] 99 8b [2] 96 91 [2] 88 8c [2] 8a 8d [2] 91 8b [2] 8d 8c [2] 91 a3 }

  condition:
    any of them
}