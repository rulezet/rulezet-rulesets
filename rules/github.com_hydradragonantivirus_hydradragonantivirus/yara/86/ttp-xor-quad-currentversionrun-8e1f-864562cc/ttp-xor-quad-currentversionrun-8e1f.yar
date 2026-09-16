rule TTP_XOR_QUAD_CurrentVersionRun_8e1f {
  strings:
    $key_8e1f = { dd 70 [2] f9 7e [2] d2 52 [2] fc 70 [2] e8 6b [2] e7 71 [2] f9 6c [2] fb 6d [2] e0 6b [2] fc 6c [2] e0 43 }

  condition:
    any of them
}