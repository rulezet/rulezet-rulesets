rule TTP_XOR_QUAD_CurrentVersionRun_e0c5 {
  strings:
    $key_e0c5 = { b3 aa [2] 97 a4 [2] bc 88 [2] 92 aa [2] 86 b1 [2] 89 ab [2] 97 b6 [2] 95 b7 [2] 8e b1 [2] 92 b6 [2] 8e 99 }

  condition:
    any of them
}