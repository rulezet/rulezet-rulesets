rule TTP_XOR_QUAD_CurrentVersionRun_127e {
  strings:
    $key_127e = { 41 11 [2] 65 1f [2] 4e 33 [2] 60 11 [2] 74 0a [2] 7b 10 [2] 65 0d [2] 67 0c [2] 7c 0a [2] 60 0d [2] 7c 22 }

  condition:
    any of them
}