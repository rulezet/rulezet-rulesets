rule TTP_XOR_QUAD_CurrentVersionRun_012e {
  strings:
    $key_012e = { 52 41 [2] 76 4f [2] 5d 63 [2] 73 41 [2] 67 5a [2] 68 40 [2] 76 5d [2] 74 5c [2] 6f 5a [2] 73 5d [2] 6f 72 }

  condition:
    any of them
}