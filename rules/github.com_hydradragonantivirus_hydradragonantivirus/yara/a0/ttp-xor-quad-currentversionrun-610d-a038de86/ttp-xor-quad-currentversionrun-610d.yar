rule TTP_XOR_QUAD_CurrentVersionRun_610d {
  strings:
    $key_610d = { 32 62 [2] 16 6c [2] 3d 40 [2] 13 62 [2] 07 79 [2] 08 63 [2] 16 7e [2] 14 7f [2] 0f 79 [2] 13 7e [2] 0f 51 }

  condition:
    any of them
}