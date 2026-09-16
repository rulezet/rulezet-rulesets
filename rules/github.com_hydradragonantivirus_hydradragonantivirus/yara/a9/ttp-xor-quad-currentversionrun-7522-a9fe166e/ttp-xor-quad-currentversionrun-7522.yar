rule TTP_XOR_QUAD_CurrentVersionRun_7522 {
  strings:
    $key_7522 = { 26 4d [2] 02 43 [2] 29 6f [2] 07 4d [2] 13 56 [2] 1c 4c [2] 02 51 [2] 00 50 [2] 1b 56 [2] 07 51 [2] 1b 7e }

  condition:
    any of them
}