rule TTP_XOR_QUAD_CurrentVersionRun_e408 {
  strings:
    $key_e408 = { b7 67 [2] 93 69 [2] b8 45 [2] 96 67 [2] 82 7c [2] 8d 66 [2] 93 7b [2] 91 7a [2] 8a 7c [2] 96 7b [2] 8a 54 }

  condition:
    any of them
}