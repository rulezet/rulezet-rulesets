rule TTP_XOR_QUAD_CurrentVersionRun_332e {
  strings:
    $key_332e = { 60 41 [2] 44 4f [2] 6f 63 [2] 41 41 [2] 55 5a [2] 5a 40 [2] 44 5d [2] 46 5c [2] 5d 5a [2] 41 5d [2] 5d 72 }

  condition:
    any of them
}