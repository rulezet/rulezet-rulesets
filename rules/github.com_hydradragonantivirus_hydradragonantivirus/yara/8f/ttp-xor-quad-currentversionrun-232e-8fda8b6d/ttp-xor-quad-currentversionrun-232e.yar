rule TTP_XOR_QUAD_CurrentVersionRun_232e {
  strings:
    $key_232e = { 70 41 [2] 54 4f [2] 7f 63 [2] 51 41 [2] 45 5a [2] 4a 40 [2] 54 5d [2] 56 5c [2] 4d 5a [2] 51 5d [2] 4d 72 }

  condition:
    any of them
}