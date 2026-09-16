rule TTP_XOR_QUAD_CurrentVersionRun_8e0e {
  strings:
    $key_8e0e = { dd 61 [2] f9 6f [2] d2 43 [2] fc 61 [2] e8 7a [2] e7 60 [2] f9 7d [2] fb 7c [2] e0 7a [2] fc 7d [2] e0 52 }

  condition:
    any of them
}