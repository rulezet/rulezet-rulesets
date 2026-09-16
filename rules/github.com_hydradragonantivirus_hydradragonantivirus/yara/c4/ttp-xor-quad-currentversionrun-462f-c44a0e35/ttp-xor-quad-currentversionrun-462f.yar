rule TTP_XOR_QUAD_CurrentVersionRun_462f {
  strings:
    $key_462f = { 15 40 [2] 31 4e [2] 1a 62 [2] 34 40 [2] 20 5b [2] 2f 41 [2] 31 5c [2] 33 5d [2] 28 5b [2] 34 5c [2] 28 73 }

  condition:
    any of them
}