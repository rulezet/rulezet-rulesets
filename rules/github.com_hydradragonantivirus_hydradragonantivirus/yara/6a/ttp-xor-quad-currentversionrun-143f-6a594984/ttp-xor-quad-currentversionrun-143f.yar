rule TTP_XOR_QUAD_CurrentVersionRun_143f {
  strings:
    $key_143f = { 47 50 [2] 63 5e [2] 48 72 [2] 66 50 [2] 72 4b [2] 7d 51 [2] 63 4c [2] 61 4d [2] 7a 4b [2] 66 4c [2] 7a 63 }

  condition:
    any of them
}