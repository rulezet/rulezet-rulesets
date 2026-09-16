rule TTP_XOR_QUAD_CurrentVersionRun_e33e {
  strings:
    $key_e33e = { b0 51 [2] 94 5f [2] bf 73 [2] 91 51 [2] 85 4a [2] 8a 50 [2] 94 4d [2] 96 4c [2] 8d 4a [2] 91 4d [2] 8d 62 }

  condition:
    any of them
}