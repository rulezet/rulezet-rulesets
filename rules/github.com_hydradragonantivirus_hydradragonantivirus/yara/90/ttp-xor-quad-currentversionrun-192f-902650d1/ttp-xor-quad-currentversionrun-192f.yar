rule TTP_XOR_QUAD_CurrentVersionRun_192f {
  strings:
    $key_192f = { 4a 40 [2] 6e 4e [2] 45 62 [2] 6b 40 [2] 7f 5b [2] 70 41 [2] 6e 5c [2] 6c 5d [2] 77 5b [2] 6b 5c [2] 77 73 }

  condition:
    any of them
}