rule TTP_XOR_QUAD_CurrentVersionRun_061c {
  strings:
    $key_061c = { 55 73 [2] 71 7d [2] 5a 51 [2] 74 73 [2] 60 68 [2] 6f 72 [2] 71 6f [2] 73 6e [2] 68 68 [2] 74 6f [2] 68 40 }

  condition:
    any of them
}