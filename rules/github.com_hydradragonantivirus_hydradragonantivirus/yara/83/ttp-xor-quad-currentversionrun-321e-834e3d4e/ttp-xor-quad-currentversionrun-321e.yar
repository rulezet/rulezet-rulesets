rule TTP_XOR_QUAD_CurrentVersionRun_321e {
  strings:
    $key_321e = { 61 71 [2] 45 7f [2] 6e 53 [2] 40 71 [2] 54 6a [2] 5b 70 [2] 45 6d [2] 47 6c [2] 5c 6a [2] 40 6d [2] 5c 42 }

  condition:
    any of them
}