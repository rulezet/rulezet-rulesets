rule TTP_XOR_QUAD_CurrentVersionRun_7a3e {
  strings:
    $key_7a3e = { 29 51 [2] 0d 5f [2] 26 73 [2] 08 51 [2] 1c 4a [2] 13 50 [2] 0d 4d [2] 0f 4c [2] 14 4a [2] 08 4d [2] 14 62 }

  condition:
    any of them
}