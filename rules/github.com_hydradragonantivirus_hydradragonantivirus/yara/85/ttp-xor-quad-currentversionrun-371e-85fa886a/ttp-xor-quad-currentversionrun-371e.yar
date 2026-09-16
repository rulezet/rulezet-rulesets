rule TTP_XOR_QUAD_CurrentVersionRun_371e {
  strings:
    $key_371e = { 64 71 [2] 40 7f [2] 6b 53 [2] 45 71 [2] 51 6a [2] 5e 70 [2] 40 6d [2] 42 6c [2] 59 6a [2] 45 6d [2] 59 42 }

  condition:
    any of them
}