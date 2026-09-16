rule TTP_XOR_QUAD_CurrentVersionRun_392f {
  strings:
    $key_392f = { 6a 40 [2] 4e 4e [2] 65 62 [2] 4b 40 [2] 5f 5b [2] 50 41 [2] 4e 5c [2] 4c 5d [2] 57 5b [2] 4b 5c [2] 57 73 }

  condition:
    any of them
}