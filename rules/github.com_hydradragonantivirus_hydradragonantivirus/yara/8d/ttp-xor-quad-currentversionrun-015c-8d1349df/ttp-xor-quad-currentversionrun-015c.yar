rule TTP_XOR_QUAD_CurrentVersionRun_015c {
  strings:
    $key_015c = { 52 33 [2] 76 3d [2] 5d 11 [2] 73 33 [2] 67 28 [2] 68 32 [2] 76 2f [2] 74 2e [2] 6f 28 [2] 73 2f [2] 6f 00 }

  condition:
    any of them
}