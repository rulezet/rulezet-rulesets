rule TTP_XOR_QUAD_CurrentVersionRun_617e {
  strings:
    $key_617e = { 32 11 [2] 16 1f [2] 3d 33 [2] 13 11 [2] 07 0a [2] 08 10 [2] 16 0d [2] 14 0c [2] 0f 0a [2] 13 0d [2] 0f 22 }

  condition:
    any of them
}