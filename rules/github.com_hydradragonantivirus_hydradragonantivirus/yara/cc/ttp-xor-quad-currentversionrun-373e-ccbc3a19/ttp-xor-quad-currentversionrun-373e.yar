rule TTP_XOR_QUAD_CurrentVersionRun_373e {
  strings:
    $key_373e = { 64 51 [2] 40 5f [2] 6b 73 [2] 45 51 [2] 51 4a [2] 5e 50 [2] 40 4d [2] 42 4c [2] 59 4a [2] 45 4d [2] 59 62 }

  condition:
    any of them
}