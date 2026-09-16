rule TTP_XOR_QUAD_CurrentVersionRun_002e {
  strings:
    $key_002e = { 53 41 [2] 77 4f [2] 5c 63 [2] 72 41 [2] 66 5a [2] 69 40 [2] 77 5d [2] 75 5c [2] 6e 5a [2] 72 5d [2] 6e 72 }

  condition:
    any of them
}