rule TTP_XOR_QUAD_CurrentVersionRun_2b2f {
  strings:
    $key_2b2f = { 78 40 [2] 5c 4e [2] 77 62 [2] 59 40 [2] 4d 5b [2] 42 41 [2] 5c 5c [2] 5e 5d [2] 45 5b [2] 59 5c [2] 45 73 }

  condition:
    any of them
}