rule TTP_XOR_QUAD_CurrentVersionRun_0a52 {
  strings:
    $key_0a52 = { 59 3d [2] 7d 33 [2] 56 1f [2] 78 3d [2] 6c 26 [2] 63 3c [2] 7d 21 [2] 7f 20 [2] 64 26 [2] 78 21 [2] 64 0e }

  condition:
    any of them
}