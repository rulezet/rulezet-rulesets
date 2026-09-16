rule TTP_XOR_QUAD_CurrentVersionRun_f96d {
  strings:
    $key_f96d = { aa 02 [2] 8e 0c [2] a5 20 [2] 8b 02 [2] 9f 19 [2] 90 03 [2] 8e 1e [2] 8c 1f [2] 97 19 [2] 8b 1e [2] 97 31 }

  condition:
    any of them
}