rule TTP_XOR_QUAD_CurrentVersionRun_e652 {
  strings:
    $key_e652 = { b5 3d [2] 91 33 [2] ba 1f [2] 94 3d [2] 80 26 [2] 8f 3c [2] 91 21 [2] 93 20 [2] 88 26 [2] 94 21 [2] 88 0e }

  condition:
    any of them
}