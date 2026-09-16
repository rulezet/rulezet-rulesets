rule TTP_XOR_QUAD_CurrentVersionRun_021e {
  strings:
    $key_021e = { 51 71 [2] 75 7f [2] 5e 53 [2] 70 71 [2] 64 6a [2] 6b 70 [2] 75 6d [2] 77 6c [2] 6c 6a [2] 70 6d [2] 6c 42 }

  condition:
    any of them
}