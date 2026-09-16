rule TTP_XOR_QUAD_CurrentVersionRun_242e {
  strings:
    $key_242e = { 77 41 [2] 53 4f [2] 78 63 [2] 56 41 [2] 42 5a [2] 4d 40 [2] 53 5d [2] 51 5c [2] 4a 5a [2] 56 5d [2] 4a 72 }

  condition:
    any of them
}