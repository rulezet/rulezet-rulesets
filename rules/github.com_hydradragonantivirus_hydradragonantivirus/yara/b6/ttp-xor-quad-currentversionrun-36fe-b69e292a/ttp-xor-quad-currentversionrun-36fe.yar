rule TTP_XOR_QUAD_CurrentVersionRun_36fe {
  strings:
    $key_36fe = { 65 91 [2] 41 9f [2] 6a b3 [2] 44 91 [2] 50 8a [2] 5f 90 [2] 41 8d [2] 43 8c [2] 58 8a [2] 44 8d [2] 58 a2 }

  condition:
    any of them
}