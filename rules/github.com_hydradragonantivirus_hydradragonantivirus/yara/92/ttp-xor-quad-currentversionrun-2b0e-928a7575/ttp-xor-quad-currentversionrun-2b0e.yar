rule TTP_XOR_QUAD_CurrentVersionRun_2b0e {
  strings:
    $key_2b0e = { 78 61 [2] 5c 6f [2] 77 43 [2] 59 61 [2] 4d 7a [2] 42 60 [2] 5c 7d [2] 5e 7c [2] 45 7a [2] 59 7d [2] 45 52 }

  condition:
    any of them
}