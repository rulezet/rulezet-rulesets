rule TTP_XOR_QUAD_CurrentVersionRun_1cfe {
  strings:
    $key_1cfe = { 4f 91 [2] 6b 9f [2] 40 b3 [2] 6e 91 [2] 7a 8a [2] 75 90 [2] 6b 8d [2] 69 8c [2] 72 8a [2] 6e 8d [2] 72 a2 }

  condition:
    any of them
}