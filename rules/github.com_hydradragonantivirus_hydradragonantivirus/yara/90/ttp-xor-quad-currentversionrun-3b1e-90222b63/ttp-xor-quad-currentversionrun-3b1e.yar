rule TTP_XOR_QUAD_CurrentVersionRun_3b1e {
  strings:
    $key_3b1e = { 68 71 [2] 4c 7f [2] 67 53 [2] 49 71 [2] 5d 6a [2] 52 70 [2] 4c 6d [2] 4e 6c [2] 55 6a [2] 49 6d [2] 55 42 }

  condition:
    any of them
}