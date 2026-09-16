rule TTP_XOR_QUAD_CurrentVersionRun_160e {
  strings:
    $key_160e = { 45 61 [2] 61 6f [2] 4a 43 [2] 64 61 [2] 70 7a [2] 7f 60 [2] 61 7d [2] 63 7c [2] 78 7a [2] 64 7d [2] 78 52 }

  condition:
    any of them
}