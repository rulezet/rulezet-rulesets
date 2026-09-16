rule TTP_XOR_QUAD_CurrentVersionRun_562f {
  strings:
    $key_562f = { 05 40 [2] 21 4e [2] 0a 62 [2] 24 40 [2] 30 5b [2] 3f 41 [2] 21 5c [2] 23 5d [2] 38 5b [2] 24 5c [2] 38 73 }

  condition:
    any of them
}