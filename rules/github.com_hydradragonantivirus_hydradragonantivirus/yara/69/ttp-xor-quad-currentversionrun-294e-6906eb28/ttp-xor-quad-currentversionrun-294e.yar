rule TTP_XOR_QUAD_CurrentVersionRun_294e {
  strings:
    $key_294e = { 7a 21 [2] 5e 2f [2] 75 03 [2] 5b 21 [2] 4f 3a [2] 40 20 [2] 5e 3d [2] 5c 3c [2] 47 3a [2] 5b 3d [2] 47 12 }

  condition:
    any of them
}