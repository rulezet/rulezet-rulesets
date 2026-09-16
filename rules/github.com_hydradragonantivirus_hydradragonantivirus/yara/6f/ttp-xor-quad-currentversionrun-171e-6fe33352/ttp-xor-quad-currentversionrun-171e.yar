rule TTP_XOR_QUAD_CurrentVersionRun_171e {
  strings:
    $key_171e = { 44 71 [2] 60 7f [2] 4b 53 [2] 65 71 [2] 71 6a [2] 7e 70 [2] 60 6d [2] 62 6c [2] 79 6a [2] 65 6d [2] 79 42 }

  condition:
    any of them
}