rule TTP_XOR_QUAD_CurrentVersionRun_356f {
  strings:
    $key_356f = { 66 00 [2] 42 0e [2] 69 22 [2] 47 00 [2] 53 1b [2] 5c 01 [2] 42 1c [2] 40 1d [2] 5b 1b [2] 47 1c [2] 5b 33 }

  condition:
    any of them
}