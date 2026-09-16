rule TTP_XOR_QUAD_CurrentVersionRun_183e {
  strings:
    $key_183e = { 4b 51 [2] 6f 5f [2] 44 73 [2] 6a 51 [2] 7e 4a [2] 71 50 [2] 6f 4d [2] 6d 4c [2] 76 4a [2] 6a 4d [2] 76 62 }

  condition:
    any of them
}