rule TTP_XOR_QUAD_CurrentVersionRun_f932 {
  strings:
    $key_f932 = { aa 5d [2] 8e 53 [2] a5 7f [2] 8b 5d [2] 9f 46 [2] 90 5c [2] 8e 41 [2] 8c 40 [2] 97 46 [2] 8b 41 [2] 97 6e }

  condition:
    any of them
}