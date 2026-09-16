rule TTP_XOR_QUAD_CurrentVersionRun_e64e {
  strings:
    $key_e64e = { b5 21 [2] 91 2f [2] ba 03 [2] 94 21 [2] 80 3a [2] 8f 20 [2] 91 3d [2] 93 3c [2] 88 3a [2] 94 3d [2] 88 12 }

  condition:
    any of them
}