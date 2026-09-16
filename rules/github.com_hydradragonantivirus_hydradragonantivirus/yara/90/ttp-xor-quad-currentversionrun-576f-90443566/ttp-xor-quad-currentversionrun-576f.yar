rule TTP_XOR_QUAD_CurrentVersionRun_576f {
  strings:
    $key_576f = { 04 00 [2] 20 0e [2] 0b 22 [2] 25 00 [2] 31 1b [2] 3e 01 [2] 20 1c [2] 22 1d [2] 39 1b [2] 25 1c [2] 39 33 }

  condition:
    any of them
}