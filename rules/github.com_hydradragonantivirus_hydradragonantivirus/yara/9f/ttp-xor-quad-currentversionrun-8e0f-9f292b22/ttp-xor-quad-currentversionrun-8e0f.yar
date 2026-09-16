rule TTP_XOR_QUAD_CurrentVersionRun_8e0f {
  strings:
    $key_8e0f = { dd 60 [2] f9 6e [2] d2 42 [2] fc 60 [2] e8 7b [2] e7 61 [2] f9 7c [2] fb 7d [2] e0 7b [2] fc 7c [2] e0 53 }

  condition:
    any of them
}