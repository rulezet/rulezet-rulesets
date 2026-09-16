rule TTP_XOR_QUAD_CurrentVersionRun_082f {
  strings:
    $key_082f = { 5b 40 [2] 7f 4e [2] 54 62 [2] 7a 40 [2] 6e 5b [2] 61 41 [2] 7f 5c [2] 7d 5d [2] 66 5b [2] 7a 5c [2] 66 73 }

  condition:
    any of them
}