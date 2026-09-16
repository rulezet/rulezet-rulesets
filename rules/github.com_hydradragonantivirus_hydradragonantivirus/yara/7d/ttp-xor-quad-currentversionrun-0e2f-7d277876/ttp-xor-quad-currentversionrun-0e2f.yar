rule TTP_XOR_QUAD_CurrentVersionRun_0e2f {
  strings:
    $key_0e2f = { 5d 40 [2] 79 4e [2] 52 62 [2] 7c 40 [2] 68 5b [2] 67 41 [2] 79 5c [2] 7b 5d [2] 60 5b [2] 7c 5c [2] 60 73 }

  condition:
    any of them
}