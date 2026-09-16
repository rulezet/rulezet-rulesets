rule TTP_XOR_QUAD_CurrentVersionRun_690c {
  strings:
    $key_690c = { 3a 63 [2] 1e 6d [2] 35 41 [2] 1b 63 [2] 0f 78 [2] 00 62 [2] 1e 7f [2] 1c 7e [2] 07 78 [2] 1b 7f [2] 07 50 }

  condition:
    any of them
}