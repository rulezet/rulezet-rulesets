rule TTP_XOR_QUAD_CurrentVersionRun_e2f9 {
  strings:
    $key_e2f9 = { b1 96 [2] 95 98 [2] be b4 [2] 90 96 [2] 84 8d [2] 8b 97 [2] 95 8a [2] 97 8b [2] 8c 8d [2] 90 8a [2] 8c a5 }

  condition:
    any of them
}