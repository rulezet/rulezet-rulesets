rule TTP_XOR_QUAD_CurrentVersionRun_e451 {
  strings:
    $key_e451 = { b7 3e [2] 93 30 [2] b8 1c [2] 96 3e [2] 82 25 [2] 8d 3f [2] 93 22 [2] 91 23 [2] 8a 25 [2] 96 22 [2] 8a 0d }

  condition:
    any of them
}