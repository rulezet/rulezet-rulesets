rule TTP_XOR_QUAD_CurrentVersionRun_695e {
  strings:
    $key_695e = { 3a 31 [2] 1e 3f [2] 35 13 [2] 1b 31 [2] 0f 2a [2] 00 30 [2] 1e 2d [2] 1c 2c [2] 07 2a [2] 1b 2d [2] 07 02 }

  condition:
    any of them
}