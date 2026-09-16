rule TTP_XOR_QUAD_CurrentVersionRun_127b {
  strings:
    $key_127b = { 41 14 [2] 65 1a [2] 4e 36 [2] 60 14 [2] 74 0f [2] 7b 15 [2] 65 08 [2] 67 09 [2] 7c 0f [2] 60 08 [2] 7c 27 }

  condition:
    any of them
}