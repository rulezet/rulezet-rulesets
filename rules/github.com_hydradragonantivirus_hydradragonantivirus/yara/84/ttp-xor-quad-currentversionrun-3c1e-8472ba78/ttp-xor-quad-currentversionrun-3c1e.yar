rule TTP_XOR_QUAD_CurrentVersionRun_3c1e {
  strings:
    $key_3c1e = { 6f 71 [2] 4b 7f [2] 60 53 [2] 4e 71 [2] 5a 6a [2] 55 70 [2] 4b 6d [2] 49 6c [2] 52 6a [2] 4e 6d [2] 52 42 }

  condition:
    any of them
}