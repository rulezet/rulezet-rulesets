rule TTP_XOR_QUAD_CurrentVersionRun_e471 {
  strings:
    $key_e471 = { b7 1e [2] 93 10 [2] b8 3c [2] 96 1e [2] 82 05 [2] 8d 1f [2] 93 02 [2] 91 03 [2] 8a 05 [2] 96 02 [2] 8a 2d }

  condition:
    any of them
}