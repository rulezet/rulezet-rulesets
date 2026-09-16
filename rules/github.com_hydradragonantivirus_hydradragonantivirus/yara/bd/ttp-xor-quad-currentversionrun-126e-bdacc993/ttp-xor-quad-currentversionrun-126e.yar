rule TTP_XOR_QUAD_CurrentVersionRun_126e {
  strings:
    $key_126e = { 41 01 [2] 65 0f [2] 4e 23 [2] 60 01 [2] 74 1a [2] 7b 00 [2] 65 1d [2] 67 1c [2] 7c 1a [2] 60 1d [2] 7c 32 }

  condition:
    any of them
}