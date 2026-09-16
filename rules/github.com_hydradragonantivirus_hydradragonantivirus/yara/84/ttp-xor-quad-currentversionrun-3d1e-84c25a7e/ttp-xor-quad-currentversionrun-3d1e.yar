rule TTP_XOR_QUAD_CurrentVersionRun_3d1e {
  strings:
    $key_3d1e = { 6e 71 [2] 4a 7f [2] 61 53 [2] 4f 71 [2] 5b 6a [2] 54 70 [2] 4a 6d [2] 48 6c [2] 53 6a [2] 4f 6d [2] 53 42 }

  condition:
    any of them
}