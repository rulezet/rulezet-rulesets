rule TTP_XOR_QUAD_CurrentVersionRun_553e {
  strings:
    $key_553e = { 06 51 [2] 22 5f [2] 09 73 [2] 27 51 [2] 33 4a [2] 3c 50 [2] 22 4d [2] 20 4c [2] 3b 4a [2] 27 4d [2] 3b 62 }

  condition:
    any of them
}