rule TTP_XOR_QUAD_CurrentVersionRun_9a0f {
  strings:
    $key_9a0f = { c9 60 [2] ed 6e [2] c6 42 [2] e8 60 [2] fc 7b [2] f3 61 [2] ed 7c [2] ef 7d [2] f4 7b [2] e8 7c [2] f4 53 }

  condition:
    any of them
}