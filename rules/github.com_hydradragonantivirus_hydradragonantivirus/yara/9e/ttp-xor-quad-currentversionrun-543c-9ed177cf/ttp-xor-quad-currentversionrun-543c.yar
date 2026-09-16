rule TTP_XOR_QUAD_CurrentVersionRun_543c {
  strings:
    $key_543c = { 07 53 [2] 23 5d [2] 08 71 [2] 26 53 [2] 32 48 [2] 3d 52 [2] 23 4f [2] 21 4e [2] 3a 48 [2] 26 4f [2] 3a 60 }

  condition:
    any of them
}