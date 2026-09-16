rule TTP_XOR_QUAD_CurrentVersionRun_020e {
  strings:
    $key_020e = { 51 61 [2] 75 6f [2] 5e 43 [2] 70 61 [2] 64 7a [2] 6b 60 [2] 75 7d [2] 77 7c [2] 6c 7a [2] 70 7d [2] 6c 52 }

  condition:
    any of them
}