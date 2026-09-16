rule TTP_XOR_QUAD_CurrentVersionRun_ebff {
  strings:
    $key_ebff = { b8 90 [2] 9c 9e [2] b7 b2 [2] 99 90 [2] 8d 8b [2] 82 91 [2] 9c 8c [2] 9e 8d [2] 85 8b [2] 99 8c [2] 85 a3 }

  condition:
    any of them
}