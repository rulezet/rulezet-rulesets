rule TTP_XOR_QUAD_CurrentVersionRun_610c {
  strings:
    $key_610c = { 32 63 [2] 16 6d [2] 3d 41 [2] 13 63 [2] 07 78 [2] 08 62 [2] 16 7f [2] 14 7e [2] 0f 78 [2] 13 7f [2] 0f 50 }

  condition:
    any of them
}