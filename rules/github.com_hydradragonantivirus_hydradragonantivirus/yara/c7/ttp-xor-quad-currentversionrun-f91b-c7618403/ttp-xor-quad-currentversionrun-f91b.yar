rule TTP_XOR_QUAD_CurrentVersionRun_f91b {
  strings:
    $key_f91b = { aa 74 [2] 8e 7a [2] a5 56 [2] 8b 74 [2] 9f 6f [2] 90 75 [2] 8e 68 [2] 8c 69 [2] 97 6f [2] 8b 68 [2] 97 47 }

  condition:
    any of them
}