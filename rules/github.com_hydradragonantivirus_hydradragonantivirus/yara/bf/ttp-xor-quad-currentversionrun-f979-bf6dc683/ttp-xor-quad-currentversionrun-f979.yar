rule TTP_XOR_QUAD_CurrentVersionRun_f979 {
  strings:
    $key_f979 = { aa 16 [2] 8e 18 [2] a5 34 [2] 8b 16 [2] 9f 0d [2] 90 17 [2] 8e 0a [2] 8c 0b [2] 97 0d [2] 8b 0a [2] 97 25 }

  condition:
    any of them
}