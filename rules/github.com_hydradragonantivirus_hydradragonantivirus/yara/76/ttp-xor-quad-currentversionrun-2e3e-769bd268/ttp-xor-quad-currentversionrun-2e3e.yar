rule TTP_XOR_QUAD_CurrentVersionRun_2e3e {
  strings:
    $key_2e3e = { 7d 51 [2] 59 5f [2] 72 73 [2] 5c 51 [2] 48 4a [2] 47 50 [2] 59 4d [2] 5b 4c [2] 40 4a [2] 5c 4d [2] 40 62 }

  condition:
    any of them
}