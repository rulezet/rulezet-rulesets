rule TTP_XOR_QUAD_CurrentVersionRun_e440 {
  strings:
    $key_e440 = { b7 2f [2] 93 21 [2] b8 0d [2] 96 2f [2] 82 34 [2] 8d 2e [2] 93 33 [2] 91 32 [2] 8a 34 [2] 96 33 [2] 8a 1c }

  condition:
    any of them
}