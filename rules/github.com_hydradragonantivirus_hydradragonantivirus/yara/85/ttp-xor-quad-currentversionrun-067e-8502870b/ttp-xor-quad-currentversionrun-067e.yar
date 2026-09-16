rule TTP_XOR_QUAD_CurrentVersionRun_067e {
  strings:
    $key_067e = { 55 11 [2] 71 1f [2] 5a 33 [2] 74 11 [2] 60 0a [2] 6f 10 [2] 71 0d [2] 73 0c [2] 68 0a [2] 74 0d [2] 68 22 }

  condition:
    any of them
}