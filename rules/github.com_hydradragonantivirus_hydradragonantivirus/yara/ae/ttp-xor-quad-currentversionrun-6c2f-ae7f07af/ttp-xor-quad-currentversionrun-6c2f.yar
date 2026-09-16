rule TTP_XOR_QUAD_CurrentVersionRun_6c2f {
  strings:
    $key_6c2f = { 3f 40 [2] 1b 4e [2] 30 62 [2] 1e 40 [2] 0a 5b [2] 05 41 [2] 1b 5c [2] 19 5d [2] 02 5b [2] 1e 5c [2] 02 73 }

  condition:
    any of them
}