rule TTP_XOR_QUAD_CurrentVersionRun_581e {
  strings:
    $key_581e = { 0b 71 [2] 2f 7f [2] 04 53 [2] 2a 71 [2] 3e 6a [2] 31 70 [2] 2f 6d [2] 2d 6c [2] 36 6a [2] 2a 6d [2] 36 42 }

  condition:
    any of them
}