rule TTP_XOR_QUAD_CurrentVersionRun_616c {
  strings:
    $key_616c = { 32 03 [2] 16 0d [2] 3d 21 [2] 13 03 [2] 07 18 [2] 08 02 [2] 16 1f [2] 14 1e [2] 0f 18 [2] 13 1f [2] 0f 30 }

  condition:
    any of them
}