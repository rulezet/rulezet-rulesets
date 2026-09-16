rule TTP_XOR_QUAD_CurrentVersionRun_2b2e {
  strings:
    $key_2b2e = { 78 41 [2] 5c 4f [2] 77 63 [2] 59 41 [2] 4d 5a [2] 42 40 [2] 5c 5d [2] 5e 5c [2] 45 5a [2] 59 5d [2] 45 72 }

  condition:
    any of them
}