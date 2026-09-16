rule TTP_XOR_QUAD_CurrentVersionRun_493e {
  strings:
    $key_493e = { 1a 51 [2] 3e 5f [2] 15 73 [2] 3b 51 [2] 2f 4a [2] 20 50 [2] 3e 4d [2] 3c 4c [2] 27 4a [2] 3b 4d [2] 27 62 }

  condition:
    any of them
}