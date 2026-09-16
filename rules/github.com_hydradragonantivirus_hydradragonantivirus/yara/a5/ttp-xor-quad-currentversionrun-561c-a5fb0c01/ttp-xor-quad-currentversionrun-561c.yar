rule TTP_XOR_QUAD_CurrentVersionRun_561c {
  strings:
    $key_561c = { 05 73 [2] 21 7d [2] 0a 51 [2] 24 73 [2] 30 68 [2] 3f 72 [2] 21 6f [2] 23 6e [2] 38 68 [2] 24 6f [2] 38 40 }

  condition:
    any of them
}