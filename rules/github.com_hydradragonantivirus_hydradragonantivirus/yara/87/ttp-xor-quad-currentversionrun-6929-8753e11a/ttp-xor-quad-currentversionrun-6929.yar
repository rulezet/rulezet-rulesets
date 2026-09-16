rule TTP_XOR_QUAD_CurrentVersionRun_6929 {
  strings:
    $key_6929 = { 3a 46 [2] 1e 48 [2] 35 64 [2] 1b 46 [2] 0f 5d [2] 00 47 [2] 1e 5a [2] 1c 5b [2] 07 5d [2] 1b 5a [2] 07 75 }

  condition:
    any of them
}