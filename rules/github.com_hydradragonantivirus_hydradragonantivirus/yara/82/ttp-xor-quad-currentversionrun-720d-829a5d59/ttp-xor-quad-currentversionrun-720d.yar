rule TTP_XOR_QUAD_CurrentVersionRun_720d {
  strings:
    $key_720d = { 21 62 [2] 05 6c [2] 2e 40 [2] 00 62 [2] 14 79 [2] 1b 63 [2] 05 7e [2] 07 7f [2] 1c 79 [2] 00 7e [2] 1c 51 }

  condition:
    any of them
}