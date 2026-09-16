rule TTP_XOR_QUAD_CurrentVersionRun_f22a {
  strings:
    $key_f22a = { a1 45 [2] 85 4b [2] ae 67 [2] 80 45 [2] 94 5e [2] 9b 44 [2] 85 59 [2] 87 58 [2] 9c 5e [2] 80 59 [2] 9c 76 }

  condition:
    any of them
}