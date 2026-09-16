rule TTP_XOR_QUAD_CurrentVersionRun_124c {
  strings:
    $key_124c = { 41 23 [2] 65 2d [2] 4e 01 [2] 60 23 [2] 74 38 [2] 7b 22 [2] 65 3f [2] 67 3e [2] 7c 38 [2] 60 3f [2] 7c 10 }

  condition:
    any of them
}