rule TTP_XOR_QUAD_CurrentVersionRun_377e {
  strings:
    $key_377e = { 64 11 [2] 40 1f [2] 6b 33 [2] 45 11 [2] 51 0a [2] 5e 10 [2] 40 0d [2] 42 0c [2] 59 0a [2] 45 0d [2] 59 22 }

  condition:
    any of them
}