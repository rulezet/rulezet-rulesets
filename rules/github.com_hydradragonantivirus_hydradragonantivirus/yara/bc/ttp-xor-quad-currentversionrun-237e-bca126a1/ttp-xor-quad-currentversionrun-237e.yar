rule TTP_XOR_QUAD_CurrentVersionRun_237e {
  strings:
    $key_237e = { 70 11 [2] 54 1f [2] 7f 33 [2] 51 11 [2] 45 0a [2] 4a 10 [2] 54 0d [2] 56 0c [2] 4d 0a [2] 51 0d [2] 4d 22 }

  condition:
    any of them
}