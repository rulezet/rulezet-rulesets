rule TTP_XOR_QUAD_CurrentVersionRun_e049 {
  strings:
    $key_e049 = { b3 26 [2] 97 28 [2] bc 04 [2] 92 26 [2] 86 3d [2] 89 27 [2] 97 3a [2] 95 3b [2] 8e 3d [2] 92 3a [2] 8e 15 }

  condition:
    any of them
}