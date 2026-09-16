rule TTP_XOR_QUAD_CurrentVersionRun_110e {
  strings:
    $key_110e = { 42 61 [2] 66 6f [2] 4d 43 [2] 63 61 [2] 77 7a [2] 78 60 [2] 66 7d [2] 64 7c [2] 7f 7a [2] 63 7d [2] 7f 52 }

  condition:
    any of them
}