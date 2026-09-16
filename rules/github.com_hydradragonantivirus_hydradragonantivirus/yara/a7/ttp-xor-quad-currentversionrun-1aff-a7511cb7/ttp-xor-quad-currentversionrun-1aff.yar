rule TTP_XOR_QUAD_CurrentVersionRun_1aff {
  strings:
    $key_1aff = { 49 90 [2] 6d 9e [2] 46 b2 [2] 68 90 [2] 7c 8b [2] 73 91 [2] 6d 8c [2] 6f 8d [2] 74 8b [2] 68 8c [2] 74 a3 }

  condition:
    any of them
}