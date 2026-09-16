rule TTP_XOR_QUAD_CurrentVersionRun_ef5c {
  strings:
    $key_ef5c = { bc 33 [2] 98 3d [2] b3 11 [2] 9d 33 [2] 89 28 [2] 86 32 [2] 98 2f [2] 9a 2e [2] 81 28 [2] 9d 2f [2] 81 00 }

  condition:
    any of them
}