rule TTP_XOR_QUAD_CurrentVersionRun_7aff {
  strings:
    $key_7aff = { 29 90 [2] 0d 9e [2] 26 b2 [2] 08 90 [2] 1c 8b [2] 13 91 [2] 0d 8c [2] 0f 8d [2] 14 8b [2] 08 8c [2] 14 a3 }

  condition:
    any of them
}