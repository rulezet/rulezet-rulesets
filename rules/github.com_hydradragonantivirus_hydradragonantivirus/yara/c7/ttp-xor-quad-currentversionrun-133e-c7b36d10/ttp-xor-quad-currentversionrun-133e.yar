rule TTP_XOR_QUAD_CurrentVersionRun_133e {
  strings:
    $key_133e = { 40 51 [2] 64 5f [2] 4f 73 [2] 61 51 [2] 75 4a [2] 7a 50 [2] 64 4d [2] 66 4c [2] 7d 4a [2] 61 4d [2] 7d 62 }

  condition:
    any of them
}