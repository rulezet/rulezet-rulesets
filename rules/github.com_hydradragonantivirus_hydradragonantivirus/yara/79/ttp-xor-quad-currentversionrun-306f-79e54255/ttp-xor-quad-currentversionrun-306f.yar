rule TTP_XOR_QUAD_CurrentVersionRun_306f {
  strings:
    $key_306f = { 63 00 [2] 47 0e [2] 6c 22 [2] 42 00 [2] 56 1b [2] 59 01 [2] 47 1c [2] 45 1d [2] 5e 1b [2] 42 1c [2] 5e 33 }

  condition:
    any of them
}