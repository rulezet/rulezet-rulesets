rule TTP_XOR_QUAD_CurrentVersionRun_f924 {
  strings:
    $key_f924 = { aa 4b [2] 8e 45 [2] a5 69 [2] 8b 4b [2] 9f 50 [2] 90 4a [2] 8e 57 [2] 8c 56 [2] 97 50 [2] 8b 57 [2] 97 78 }

  condition:
    any of them
}