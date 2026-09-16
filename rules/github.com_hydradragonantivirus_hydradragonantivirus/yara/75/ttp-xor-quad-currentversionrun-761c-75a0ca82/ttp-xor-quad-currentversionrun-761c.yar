rule TTP_XOR_QUAD_CurrentVersionRun_761c {
  strings:
    $key_761c = { 25 73 [2] 01 7d [2] 2a 51 [2] 04 73 [2] 10 68 [2] 1f 72 [2] 01 6f [2] 03 6e [2] 18 68 [2] 04 6f [2] 18 40 }

  condition:
    any of them
}