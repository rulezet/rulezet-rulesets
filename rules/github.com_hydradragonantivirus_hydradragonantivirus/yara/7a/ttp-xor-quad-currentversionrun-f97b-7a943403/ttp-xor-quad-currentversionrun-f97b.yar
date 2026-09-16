rule TTP_XOR_QUAD_CurrentVersionRun_f97b {
  strings:
    $key_f97b = { aa 14 [2] 8e 1a [2] a5 36 [2] 8b 14 [2] 9f 0f [2] 90 15 [2] 8e 08 [2] 8c 09 [2] 97 0f [2] 8b 08 [2] 97 27 }

  condition:
    any of them
}