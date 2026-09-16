rule TTP_XOR_QUAD_CurrentVersionRun_690d {
  strings:
    $key_690d = { 3a 62 [2] 1e 6c [2] 35 40 [2] 1b 62 [2] 0f 79 [2] 00 63 [2] 1e 7e [2] 1c 7f [2] 07 79 [2] 1b 7e [2] 07 51 }

  condition:
    any of them
}