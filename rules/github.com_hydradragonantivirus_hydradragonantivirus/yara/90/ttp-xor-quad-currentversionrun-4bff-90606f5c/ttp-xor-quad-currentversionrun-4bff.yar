rule TTP_XOR_QUAD_CurrentVersionRun_4bff {
  strings:
    $key_4bff = { 18 90 [2] 3c 9e [2] 17 b2 [2] 39 90 [2] 2d 8b [2] 22 91 [2] 3c 8c [2] 3e 8d [2] 25 8b [2] 39 8c [2] 25 a3 }

  condition:
    any of them
}