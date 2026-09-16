rule TTP_XOR_QUAD_CurrentVersionRun_000e {
  strings:
    $key_000e = { 53 61 [2] 77 6f [2] 5c 43 [2] 72 61 [2] 66 7a [2] 69 60 [2] 77 7d [2] 75 7c [2] 6e 7a [2] 72 7d [2] 6e 52 }

  condition:
    any of them
}