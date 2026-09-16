rule TTP_XOR_QUAD_CurrentVersionRun_f17b {
  strings:
    $key_f17b = { a2 14 [2] 86 1a [2] ad 36 [2] 83 14 [2] 97 0f [2] 98 15 [2] 86 08 [2] 84 09 [2] 9f 0f [2] 83 08 [2] 9f 27 }

  condition:
    any of them
}