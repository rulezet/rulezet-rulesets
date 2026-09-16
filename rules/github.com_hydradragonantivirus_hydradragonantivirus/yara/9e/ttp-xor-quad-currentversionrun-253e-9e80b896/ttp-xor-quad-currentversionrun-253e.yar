rule TTP_XOR_QUAD_CurrentVersionRun_253e {
  strings:
    $key_253e = { 76 51 [2] 52 5f [2] 79 73 [2] 57 51 [2] 43 4a [2] 4c 50 [2] 52 4d [2] 50 4c [2] 4b 4a [2] 57 4d [2] 4b 62 }

  condition:
    any of them
}