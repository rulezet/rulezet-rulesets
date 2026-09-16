rule TTP_XOR_QUAD_CurrentVersionRun_f33e {
  strings:
    $key_f33e = { a0 51 [2] 84 5f [2] af 73 [2] 81 51 [2] 95 4a [2] 9a 50 [2] 84 4d [2] 86 4c [2] 9d 4a [2] 81 4d [2] 9d 62 }

  condition:
    any of them
}