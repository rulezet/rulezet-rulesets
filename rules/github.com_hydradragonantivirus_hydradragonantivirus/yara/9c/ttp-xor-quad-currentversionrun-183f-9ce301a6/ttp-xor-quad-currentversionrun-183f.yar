rule TTP_XOR_QUAD_CurrentVersionRun_183f {
  strings:
    $key_183f = { 4b 50 [2] 6f 5e [2] 44 72 [2] 6a 50 [2] 7e 4b [2] 71 51 [2] 6f 4c [2] 6d 4d [2] 76 4b [2] 6a 4c [2] 76 63 }

  condition:
    any of them
}