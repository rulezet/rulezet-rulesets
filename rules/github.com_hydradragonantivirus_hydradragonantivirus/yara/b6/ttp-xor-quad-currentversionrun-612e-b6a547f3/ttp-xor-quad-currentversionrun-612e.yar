rule TTP_XOR_QUAD_CurrentVersionRun_612e {
  strings:
    $key_612e = { 32 41 [2] 16 4f [2] 3d 63 [2] 13 41 [2] 07 5a [2] 08 40 [2] 16 5d [2] 14 5c [2] 0f 5a [2] 13 5d [2] 0f 72 }

  condition:
    any of them
}