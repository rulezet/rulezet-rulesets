rule TTP_XOR_QUAD_CurrentVersionRun_e57e {
  strings:
    $key_e57e = { b6 11 [2] 92 1f [2] b9 33 [2] 97 11 [2] 83 0a [2] 8c 10 [2] 92 0d [2] 90 0c [2] 8b 0a [2] 97 0d [2] 8b 22 }

  condition:
    any of them
}