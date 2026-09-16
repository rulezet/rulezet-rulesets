rule TTP_XOR_QUAD_CurrentVersionRun_6a2e {
  strings:
    $key_6a2e = { 39 41 [2] 1d 4f [2] 36 63 [2] 18 41 [2] 0c 5a [2] 03 40 [2] 1d 5d [2] 1f 5c [2] 04 5a [2] 18 5d [2] 04 72 }

  condition:
    any of them
}