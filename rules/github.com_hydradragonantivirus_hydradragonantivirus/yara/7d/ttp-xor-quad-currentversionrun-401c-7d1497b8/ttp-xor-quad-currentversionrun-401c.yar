rule TTP_XOR_QUAD_CurrentVersionRun_401c {
  strings:
    $key_401c = { 13 73 [2] 37 7d [2] 1c 51 [2] 32 73 [2] 26 68 [2] 29 72 [2] 37 6f [2] 35 6e [2] 2e 68 [2] 32 6f [2] 2e 40 }

  condition:
    any of them
}