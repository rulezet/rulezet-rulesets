rule TTP_XOR_QUAD_CurrentVersionRun_8b0f {
  strings:
    $key_8b0f = { d8 60 [2] fc 6e [2] d7 42 [2] f9 60 [2] ed 7b [2] e2 61 [2] fc 7c [2] fe 7d [2] e5 7b [2] f9 7c [2] e5 53 }

  condition:
    any of them
}