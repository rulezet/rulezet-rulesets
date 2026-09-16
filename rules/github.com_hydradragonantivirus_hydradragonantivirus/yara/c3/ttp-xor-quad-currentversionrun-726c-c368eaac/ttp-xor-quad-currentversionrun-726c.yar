rule TTP_XOR_QUAD_CurrentVersionRun_726c {
  strings:
    $key_726c = { 21 03 [2] 05 0d [2] 2e 21 [2] 00 03 [2] 14 18 [2] 1b 02 [2] 05 1f [2] 07 1e [2] 1c 18 [2] 00 1f [2] 1c 30 }

  condition:
    any of them
}