rule TTP_XOR_QUAD_CurrentVersionRun_f952 {
  strings:
    $key_f952 = { aa 3d [2] 8e 33 [2] a5 1f [2] 8b 3d [2] 9f 26 [2] 90 3c [2] 8e 21 [2] 8c 20 [2] 97 26 [2] 8b 21 [2] 97 0e }

  condition:
    any of them
}