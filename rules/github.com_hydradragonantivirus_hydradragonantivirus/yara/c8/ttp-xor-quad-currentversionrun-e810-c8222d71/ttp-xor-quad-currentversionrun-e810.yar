rule TTP_XOR_QUAD_CurrentVersionRun_e810 {
  strings:
    $key_e810 = { bb 7f [2] 9f 71 [2] b4 5d [2] 9a 7f [2] 8e 64 [2] 81 7e [2] 9f 63 [2] 9d 62 [2] 86 64 [2] 9a 63 [2] 86 4c }

  condition:
    any of them
}