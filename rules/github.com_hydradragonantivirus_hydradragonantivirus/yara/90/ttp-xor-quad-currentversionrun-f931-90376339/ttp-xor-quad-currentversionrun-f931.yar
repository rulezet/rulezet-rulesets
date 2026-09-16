rule TTP_XOR_QUAD_CurrentVersionRun_f931 {
  strings:
    $key_f931 = { aa 5e [2] 8e 50 [2] a5 7c [2] 8b 5e [2] 9f 45 [2] 90 5f [2] 8e 42 [2] 8c 43 [2] 97 45 [2] 8b 42 [2] 97 6d }

  condition:
    any of them
}