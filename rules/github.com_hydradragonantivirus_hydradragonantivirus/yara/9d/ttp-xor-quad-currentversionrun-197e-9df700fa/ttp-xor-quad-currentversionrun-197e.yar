rule TTP_XOR_QUAD_CurrentVersionRun_197e {
  strings:
    $key_197e = { 4a 11 [2] 6e 1f [2] 45 33 [2] 6b 11 [2] 7f 0a [2] 70 10 [2] 6e 0d [2] 6c 0c [2] 77 0a [2] 6b 0d [2] 77 22 }

  condition:
    any of them
}