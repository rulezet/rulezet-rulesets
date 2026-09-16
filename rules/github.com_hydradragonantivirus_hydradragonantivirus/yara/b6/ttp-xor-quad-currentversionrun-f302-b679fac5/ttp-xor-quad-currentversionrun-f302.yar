rule TTP_XOR_QUAD_CurrentVersionRun_f302 {
  strings:
    $key_f302 = { a0 6d [2] 84 63 [2] af 4f [2] 81 6d [2] 95 76 [2] 9a 6c [2] 84 71 [2] 86 70 [2] 9d 76 [2] 81 71 [2] 9d 5e }

  condition:
    any of them
}