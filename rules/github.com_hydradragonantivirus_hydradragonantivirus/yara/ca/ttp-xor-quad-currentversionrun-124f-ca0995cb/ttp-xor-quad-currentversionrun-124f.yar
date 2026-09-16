rule TTP_XOR_QUAD_CurrentVersionRun_124f {
  strings:
    $key_124f = { 41 20 [2] 65 2e [2] 4e 02 [2] 60 20 [2] 74 3b [2] 7b 21 [2] 65 3c [2] 67 3d [2] 7c 3b [2] 60 3c [2] 7c 13 }

  condition:
    any of them
}