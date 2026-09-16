rule TTP_XOR_QUAD_CurrentVersionRun_181c {
  strings:
    $key_181c = { 4b 73 [2] 6f 7d [2] 44 51 [2] 6a 73 [2] 7e 68 [2] 71 72 [2] 6f 6f [2] 6d 6e [2] 76 68 [2] 6a 6f [2] 76 40 }

  condition:
    any of them
}