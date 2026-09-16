rule TTP_XOR_QUAD_CurrentVersionRun_ef52 {
  strings:
    $key_ef52 = { bc 3d [2] 98 33 [2] b3 1f [2] 9d 3d [2] 89 26 [2] 86 3c [2] 98 21 [2] 9a 20 [2] 81 26 [2] 9d 21 [2] 81 0e }

  condition:
    any of them
}