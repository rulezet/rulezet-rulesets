rule TTP_XOR_QUAD_CurrentVersionRun_52f9 {
  strings:
    $key_52f9 = { 01 96 [2] 25 98 [2] 0e b4 [2] 20 96 [2] 34 8d [2] 3b 97 [2] 25 8a [2] 27 8b [2] 3c 8d [2] 20 8a [2] 3c a5 }

  condition:
    any of them
}