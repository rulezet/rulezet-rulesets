rule TTP_XOR_QUAD_CurrentVersionRun_e035 {
  strings:
    $key_e035 = { b3 5a [2] 97 54 [2] bc 78 [2] 92 5a [2] 86 41 [2] 89 5b [2] 97 46 [2] 95 47 [2] 8e 41 [2] 92 46 [2] 8e 69 }

  condition:
    any of them
}