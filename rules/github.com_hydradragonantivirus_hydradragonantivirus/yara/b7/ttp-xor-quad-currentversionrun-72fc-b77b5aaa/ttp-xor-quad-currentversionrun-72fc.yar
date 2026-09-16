rule TTP_XOR_QUAD_CurrentVersionRun_72fc {
  strings:
    $key_72fc = { 21 93 [2] 05 9d [2] 2e b1 [2] 00 93 [2] 14 88 [2] 1b 92 [2] 05 8f [2] 07 8e [2] 1c 88 [2] 00 8f [2] 1c a0 }

  condition:
    any of them
}