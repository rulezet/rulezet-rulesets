rule TTP_XOR_QUAD_CurrentVersionRun_0e1c {
  strings:
    $key_0e1c = { 5d 73 [2] 79 7d [2] 52 51 [2] 7c 73 [2] 68 68 [2] 67 72 [2] 79 6f [2] 7b 6e [2] 60 68 [2] 7c 6f [2] 60 40 }

  condition:
    any of them
}