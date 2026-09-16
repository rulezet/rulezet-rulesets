rule TTP_XOR_QUAD_CurrentVersionRun_e462 {
  strings:
    $key_e462 = { b7 0d [2] 93 03 [2] b8 2f [2] 96 0d [2] 82 16 [2] 8d 0c [2] 93 11 [2] 91 10 [2] 8a 16 [2] 96 11 [2] 8a 3e }

  condition:
    any of them
}