rule TTP_XOR_QUAD_CurrentVersionRun_771c {
  strings:
    $key_771c = { 24 73 [2] 00 7d [2] 2b 51 [2] 05 73 [2] 11 68 [2] 1e 72 [2] 00 6f [2] 02 6e [2] 19 68 [2] 05 6f [2] 19 40 }

  condition:
    any of them
}