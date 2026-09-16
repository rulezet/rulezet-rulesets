rule TTP_XOR_QUAD_CurrentVersionRun_f94e {
  strings:
    $key_f94e = { aa 21 [2] 8e 2f [2] a5 03 [2] 8b 21 [2] 9f 3a [2] 90 20 [2] 8e 3d [2] 8c 3c [2] 97 3a [2] 8b 3d [2] 97 12 }

  condition:
    any of them
}