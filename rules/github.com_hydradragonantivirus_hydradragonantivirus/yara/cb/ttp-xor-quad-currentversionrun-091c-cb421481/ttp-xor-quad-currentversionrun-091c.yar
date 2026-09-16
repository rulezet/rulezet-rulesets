rule TTP_XOR_QUAD_CurrentVersionRun_091c {
  strings:
    $key_091c = { 5a 73 [2] 7e 7d [2] 55 51 [2] 7b 73 [2] 6f 68 [2] 60 72 [2] 7e 6f [2] 7c 6e [2] 67 68 [2] 7b 6f [2] 67 40 }

  condition:
    any of them
}