rule TTP_XOR_QUAD_CurrentVersionRun_381e {
  strings:
    $key_381e = { 6b 71 [2] 4f 7f [2] 64 53 [2] 4a 71 [2] 5e 6a [2] 51 70 [2] 4f 6d [2] 4d 6c [2] 56 6a [2] 4a 6d [2] 56 42 }

  condition:
    any of them
}