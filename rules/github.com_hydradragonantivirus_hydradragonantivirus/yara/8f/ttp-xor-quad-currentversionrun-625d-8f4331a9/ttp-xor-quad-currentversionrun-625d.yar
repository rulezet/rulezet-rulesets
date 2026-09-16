rule TTP_XOR_QUAD_CurrentVersionRun_625d {
  strings:
    $key_625d = { 31 32 [2] 15 3c [2] 3e 10 [2] 10 32 [2] 04 29 [2] 0b 33 [2] 15 2e [2] 17 2f [2] 0c 29 [2] 10 2e [2] 0c 01 }

  condition:
    any of them
}