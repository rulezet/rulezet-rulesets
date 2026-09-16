rule TTP_XOR_QUAD_CurrentVersionRun_91ee {
  strings:
    $key_91ee = { c2 81 [2] e6 8f [2] cd a3 [2] e3 81 [2] f7 9a [2] f8 80 [2] e6 9d [2] e4 9c [2] ff 9a [2] e3 9d [2] ff b2 }

  condition:
    any of them
}