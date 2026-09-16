rule TTP_XOR_QUAD_CurrentVersionRun_e519 {
  strings:
    $key_e519 = { b6 76 [2] 92 78 [2] b9 54 [2] 97 76 [2] 83 6d [2] 8c 77 [2] 92 6a [2] 90 6b [2] 8b 6d [2] 97 6a [2] 8b 45 }

  condition:
    any of them
}