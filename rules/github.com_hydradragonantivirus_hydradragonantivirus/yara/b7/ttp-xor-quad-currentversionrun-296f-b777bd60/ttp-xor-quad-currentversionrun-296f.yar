rule TTP_XOR_QUAD_CurrentVersionRun_296f {
  strings:
    $key_296f = { 7a 00 [2] 5e 0e [2] 75 22 [2] 5b 00 [2] 4f 1b [2] 40 01 [2] 5e 1c [2] 5c 1d [2] 47 1b [2] 5b 1c [2] 47 33 }

  condition:
    any of them
}