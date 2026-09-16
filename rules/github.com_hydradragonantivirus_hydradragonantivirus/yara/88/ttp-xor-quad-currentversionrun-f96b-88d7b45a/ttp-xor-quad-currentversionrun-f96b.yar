rule TTP_XOR_QUAD_CurrentVersionRun_f96b {
  strings:
    $key_f96b = { aa 04 [2] 8e 0a [2] a5 26 [2] 8b 04 [2] 9f 1f [2] 90 05 [2] 8e 18 [2] 8c 19 [2] 97 1f [2] 8b 18 [2] 97 37 }

  condition:
    any of them
}