rule TTP_XOR_QUAD_CurrentVersionRun_613a {
  strings:
    $key_613a = { 32 55 [2] 16 5b [2] 3d 77 [2] 13 55 [2] 07 4e [2] 08 54 [2] 16 49 [2] 14 48 [2] 0f 4e [2] 13 49 [2] 0f 66 }

  condition:
    any of them
}