rule TTP_XOR_QUAD_CurrentVersionRun_060e {
  strings:
    $key_060e = { 55 61 [2] 71 6f [2] 5a 43 [2] 74 61 [2] 60 7a [2] 6f 60 [2] 71 7d [2] 73 7c [2] 68 7a [2] 74 7d [2] 68 52 }

  condition:
    any of them
}