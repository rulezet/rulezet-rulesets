rule TTP_XOR_QUAD_CurrentVersionRun_f2fe {
  strings:
    $key_f2fe = { a1 91 [2] 85 9f [2] ae b3 [2] 80 91 [2] 94 8a [2] 9b 90 [2] 85 8d [2] 87 8c [2] 9c 8a [2] 80 8d [2] 9c a2 }

  condition:
    any of them
}