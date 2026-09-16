rule TTP_XOR_QUAD_CurrentVersionRun_071e {
  strings:
    $key_071e = { 54 71 [2] 70 7f [2] 5b 53 [2] 75 71 [2] 61 6a [2] 6e 70 [2] 70 6d [2] 72 6c [2] 69 6a [2] 75 6d [2] 69 42 }

  condition:
    any of them
}