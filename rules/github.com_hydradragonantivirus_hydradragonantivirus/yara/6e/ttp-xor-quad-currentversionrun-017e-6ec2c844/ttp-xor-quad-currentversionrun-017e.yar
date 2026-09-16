rule TTP_XOR_QUAD_CurrentVersionRun_017e {
  strings:
    $key_017e = { 52 11 [2] 76 1f [2] 5d 33 [2] 73 11 [2] 67 0a [2] 68 10 [2] 76 0d [2] 74 0c [2] 6f 0a [2] 73 0d [2] 6f 22 }

  condition:
    any of them
}