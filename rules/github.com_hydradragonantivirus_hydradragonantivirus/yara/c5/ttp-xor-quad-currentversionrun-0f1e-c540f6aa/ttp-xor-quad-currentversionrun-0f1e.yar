rule TTP_XOR_QUAD_CurrentVersionRun_0f1e {
  strings:
    $key_0f1e = { 5c 71 [2] 78 7f [2] 53 53 [2] 7d 71 [2] 69 6a [2] 66 70 [2] 78 6d [2] 7a 6c [2] 61 6a [2] 7d 6d [2] 61 42 }

  condition:
    any of them
}