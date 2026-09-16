rule TTP_XOR_QUAD_CurrentVersionRun_f22d {
  strings:
    $key_f22d = { a1 42 [2] 85 4c [2] ae 60 [2] 80 42 [2] 94 59 [2] 9b 43 [2] 85 5e [2] 87 5f [2] 9c 59 [2] 80 5e [2] 9c 71 }

  condition:
    any of them
}