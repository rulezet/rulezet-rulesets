rule TTP_XOR_QUAD_CurrentVersionRun_610e {
  strings:
    $key_610e = { 32 61 [2] 16 6f [2] 3d 43 [2] 13 61 [2] 07 7a [2] 08 60 [2] 16 7d [2] 14 7c [2] 0f 7a [2] 13 7d [2] 0f 52 }

  condition:
    any of them
}