rule TTP_XOR_QUAD_CurrentVersionRun_182e {
  strings:
    $key_182e = { 4b 41 [2] 6f 4f [2] 44 63 [2] 6a 41 [2] 7e 5a [2] 71 40 [2] 6f 5d [2] 6d 5c [2] 76 5a [2] 6a 5d [2] 76 72 }

  condition:
    any of them
}