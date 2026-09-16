rule TTP_XOR_QUAD_CurrentVersionRun_3c2f {
  strings:
    $key_3c2f = { 6f 40 [2] 4b 4e [2] 60 62 [2] 4e 40 [2] 5a 5b [2] 55 41 [2] 4b 5c [2] 49 5d [2] 52 5b [2] 4e 5c [2] 52 73 }

  condition:
    any of them
}