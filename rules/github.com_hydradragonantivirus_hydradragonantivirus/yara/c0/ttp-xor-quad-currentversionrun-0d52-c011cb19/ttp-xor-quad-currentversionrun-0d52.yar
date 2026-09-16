rule TTP_XOR_QUAD_CurrentVersionRun_0d52 {
  strings:
    $key_0d52 = { 5e 3d [2] 7a 33 [2] 51 1f [2] 7f 3d [2] 6b 26 [2] 64 3c [2] 7a 21 [2] 78 20 [2] 63 26 [2] 7f 21 [2] 63 0e }

  condition:
    any of them
}