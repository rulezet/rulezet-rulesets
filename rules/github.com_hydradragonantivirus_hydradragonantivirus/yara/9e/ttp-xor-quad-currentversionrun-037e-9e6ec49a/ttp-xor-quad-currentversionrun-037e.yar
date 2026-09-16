rule TTP_XOR_QUAD_CurrentVersionRun_037e {
  strings:
    $key_037e = { 50 11 [2] 74 1f [2] 5f 33 [2] 71 11 [2] 65 0a [2] 6a 10 [2] 74 0d [2] 76 0c [2] 6d 0a [2] 71 0d [2] 6d 22 }

  condition:
    any of them
}