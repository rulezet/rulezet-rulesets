rule TTP_XOR_QUAD_CurrentVersionRun_332f {
  strings:
    $key_332f = { 60 40 [2] 44 4e [2] 6f 62 [2] 41 40 [2] 55 5b [2] 5a 41 [2] 44 5c [2] 46 5d [2] 5d 5b [2] 41 5c [2] 5d 73 }

  condition:
    any of them
}