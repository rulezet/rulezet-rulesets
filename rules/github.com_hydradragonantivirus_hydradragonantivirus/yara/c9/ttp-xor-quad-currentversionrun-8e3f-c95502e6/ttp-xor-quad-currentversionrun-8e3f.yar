rule TTP_XOR_QUAD_CurrentVersionRun_8e3f {
  strings:
    $key_8e3f = { dd 50 [2] f9 5e [2] d2 72 [2] fc 50 [2] e8 4b [2] e7 51 [2] f9 4c [2] fb 4d [2] e0 4b [2] fc 4c [2] e0 63 }

  condition:
    any of them
}