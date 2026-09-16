rule TTP_XOR_QUAD_CurrentVersionRun_e450 {
  strings:
    $key_e450 = { b7 3f [2] 93 31 [2] b8 1d [2] 96 3f [2] 82 24 [2] 8d 3e [2] 93 23 [2] 91 22 [2] 8a 24 [2] 96 23 [2] 8a 0c }

  condition:
    any of them
}