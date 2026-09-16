rule TTP_XOR_QUAD_CurrentVersionRun_792f {
  strings:
    $key_792f = { 2a 40 [2] 0e 4e [2] 25 62 [2] 0b 40 [2] 1f 5b [2] 10 41 [2] 0e 5c [2] 0c 5d [2] 17 5b [2] 0b 5c [2] 17 73 }

  condition:
    any of them
}