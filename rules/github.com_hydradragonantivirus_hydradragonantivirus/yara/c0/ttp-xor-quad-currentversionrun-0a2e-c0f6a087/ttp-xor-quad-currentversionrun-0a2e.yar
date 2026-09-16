rule TTP_XOR_QUAD_CurrentVersionRun_0a2e {
  strings:
    $key_0a2e = { 59 41 [2] 7d 4f [2] 56 63 [2] 78 41 [2] 6c 5a [2] 63 40 [2] 7d 5d [2] 7f 5c [2] 64 5a [2] 78 5d [2] 64 72 }

  condition:
    any of them
}