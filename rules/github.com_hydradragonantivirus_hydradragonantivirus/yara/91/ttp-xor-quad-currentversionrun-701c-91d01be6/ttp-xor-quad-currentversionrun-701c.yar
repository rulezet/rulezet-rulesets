rule TTP_XOR_QUAD_CurrentVersionRun_701c {
  strings:
    $key_701c = { 23 73 [2] 07 7d [2] 2c 51 [2] 02 73 [2] 16 68 [2] 19 72 [2] 07 6f [2] 05 6e [2] 1e 68 [2] 02 6f [2] 1e 40 }

  condition:
    any of them
}