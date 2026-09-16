rule TTP_XOR_QUAD_CurrentVersionRun_1dff {
  strings:
    $key_1dff = { 4e 90 [2] 6a 9e [2] 41 b2 [2] 6f 90 [2] 7b 8b [2] 74 91 [2] 6a 8c [2] 68 8d [2] 73 8b [2] 6f 8c [2] 73 a3 }

  condition:
    any of them
}