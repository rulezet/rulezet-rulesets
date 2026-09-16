rule TTP_XOR_QUAD_CurrentVersionRun_613f {
  strings:
    $key_613f = { 32 50 [2] 16 5e [2] 3d 72 [2] 13 50 [2] 07 4b [2] 08 51 [2] 16 4c [2] 14 4d [2] 0f 4b [2] 13 4c [2] 0f 63 }

  condition:
    any of them
}