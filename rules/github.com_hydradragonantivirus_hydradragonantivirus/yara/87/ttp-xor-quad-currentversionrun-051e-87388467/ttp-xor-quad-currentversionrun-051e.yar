rule TTP_XOR_QUAD_CurrentVersionRun_051e {
  strings:
    $key_051e = { 56 71 [2] 72 7f [2] 59 53 [2] 77 71 [2] 63 6a [2] 6c 70 [2] 72 6d [2] 70 6c [2] 6b 6a [2] 77 6d [2] 6b 42 }

  condition:
    any of them
}