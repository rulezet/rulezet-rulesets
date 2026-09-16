rule TTP_XOR_QUAD_CurrentVersionRun_622a {
  strings:
    $key_622a = { 31 45 [2] 15 4b [2] 3e 67 [2] 10 45 [2] 04 5e [2] 0b 44 [2] 15 59 [2] 17 58 [2] 0c 5e [2] 10 59 [2] 0c 76 }

  condition:
    any of them
}