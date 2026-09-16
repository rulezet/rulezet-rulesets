rule TTP_XOR_QUAD_CurrentVersionRun_4b1e {
  strings:
    $key_4b1e = { 18 71 [2] 3c 7f [2] 17 53 [2] 39 71 [2] 2d 6a [2] 22 70 [2] 3c 6d [2] 3e 6c [2] 25 6a [2] 39 6d [2] 25 42 }

  condition:
    any of them
}