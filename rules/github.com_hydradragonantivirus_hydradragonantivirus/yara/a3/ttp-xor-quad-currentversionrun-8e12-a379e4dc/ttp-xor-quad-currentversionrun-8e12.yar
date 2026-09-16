rule TTP_XOR_QUAD_CurrentVersionRun_8e12 {
  strings:
    $key_8e12 = { dd 7d [2] f9 73 [2] d2 5f [2] fc 7d [2] e8 66 [2] e7 7c [2] f9 61 [2] fb 60 [2] e0 66 [2] fc 61 [2] e0 4e }

  condition:
    any of them
}