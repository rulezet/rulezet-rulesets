rule TTP_XOR_QUAD_CurrentVersionRun_652f {
  strings:
    $key_652f = { 36 40 [2] 12 4e [2] 39 62 [2] 17 40 [2] 03 5b [2] 0c 41 [2] 12 5c [2] 10 5d [2] 0b 5b [2] 17 5c [2] 0b 73 }

  condition:
    any of them
}