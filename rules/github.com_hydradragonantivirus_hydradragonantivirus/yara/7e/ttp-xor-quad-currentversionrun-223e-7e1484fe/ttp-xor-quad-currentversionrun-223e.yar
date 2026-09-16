rule TTP_XOR_QUAD_CurrentVersionRun_223e {
  strings:
    $key_223e = { 71 51 [2] 55 5f [2] 7e 73 [2] 50 51 [2] 44 4a [2] 4b 50 [2] 55 4d [2] 57 4c [2] 4c 4a [2] 50 4d [2] 4c 62 }

  condition:
    any of them
}