rule TTP_XOR_QUAD_CurrentVersionRun_0e51 {
  strings:
    $key_0e51 = { 5d 3e [2] 79 30 [2] 52 1c [2] 7c 3e [2] 68 25 [2] 67 3f [2] 79 22 [2] 7b 23 [2] 60 25 [2] 7c 22 [2] 60 0d }

  condition:
    any of them
}