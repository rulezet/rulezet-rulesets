rule TTP_XOR_QUAD_CurrentVersionRun_0552 {
  strings:
    $key_0552 = { 56 3d [2] 72 33 [2] 59 1f [2] 77 3d [2] 63 26 [2] 6c 3c [2] 72 21 [2] 70 20 [2] 6b 26 [2] 77 21 [2] 6b 0e }

  condition:
    any of them
}