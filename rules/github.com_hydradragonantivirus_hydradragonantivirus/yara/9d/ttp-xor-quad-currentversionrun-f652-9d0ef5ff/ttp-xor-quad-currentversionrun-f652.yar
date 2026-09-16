rule TTP_XOR_QUAD_CurrentVersionRun_f652 {
  strings:
    $key_f652 = { a5 3d [2] 81 33 [2] aa 1f [2] 84 3d [2] 90 26 [2] 9f 3c [2] 81 21 [2] 83 20 [2] 98 26 [2] 84 21 [2] 98 0e }

  condition:
    any of them
}