rule TTP_XOR_QUAD_CurrentVersionRun_081e {
  strings:
    $key_081e = { 5b 71 [2] 7f 7f [2] 54 53 [2] 7a 71 [2] 6e 6a [2] 61 70 [2] 7f 6d [2] 7d 6c [2] 66 6a [2] 7a 6d [2] 66 42 }

  condition:
    any of them
}