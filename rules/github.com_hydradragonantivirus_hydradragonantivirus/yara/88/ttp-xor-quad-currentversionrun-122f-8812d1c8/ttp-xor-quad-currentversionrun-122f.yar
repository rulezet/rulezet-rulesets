rule TTP_XOR_QUAD_CurrentVersionRun_122f {
  strings:
    $key_122f = { 41 40 [2] 65 4e [2] 4e 62 [2] 60 40 [2] 74 5b [2] 7b 41 [2] 65 5c [2] 67 5d [2] 7c 5b [2] 60 5c [2] 7c 73 }

  condition:
    any of them
}