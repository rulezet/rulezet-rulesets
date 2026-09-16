rule TTP_XOR_QUAD_CurrentVersionRun_6932 {
  strings:
    $key_6932 = { 3a 5d [2] 1e 53 [2] 35 7f [2] 1b 5d [2] 0f 46 [2] 00 5c [2] 1e 41 [2] 1c 40 [2] 07 46 [2] 1b 41 [2] 07 6e }

  condition:
    any of them
}