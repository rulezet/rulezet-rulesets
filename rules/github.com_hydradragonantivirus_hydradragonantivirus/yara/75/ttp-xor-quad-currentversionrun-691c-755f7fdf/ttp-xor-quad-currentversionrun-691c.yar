rule TTP_XOR_QUAD_CurrentVersionRun_691c {
  strings:
    $key_691c = { 3a 73 [2] 1e 7d [2] 35 51 [2] 1b 73 [2] 0f 68 [2] 00 72 [2] 1e 6f [2] 1c 6e [2] 07 68 [2] 1b 6f [2] 07 40 }

  condition:
    any of them
}