rule TTP_XOR_QUAD_CurrentVersionRun_613e {
  strings:
    $key_613e = { 32 51 [2] 16 5f [2] 3d 73 [2] 13 51 [2] 07 4a [2] 08 50 [2] 16 4d [2] 14 4c [2] 0f 4a [2] 13 4d [2] 0f 62 }

  condition:
    any of them
}