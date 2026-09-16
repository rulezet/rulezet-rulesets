rule TTP_XOR_QUAD_CurrentVersionRun_e0c4 {
  strings:
    $key_e0c4 = { b3 ab [2] 97 a5 [2] bc 89 [2] 92 ab [2] 86 b0 [2] 89 aa [2] 97 b7 [2] 95 b6 [2] 8e b0 [2] 92 b7 [2] 8e 98 }

  condition:
    any of them
}