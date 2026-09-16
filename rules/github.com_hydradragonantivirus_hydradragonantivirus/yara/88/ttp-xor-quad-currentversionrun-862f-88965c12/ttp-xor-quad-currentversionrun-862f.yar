rule TTP_XOR_QUAD_CurrentVersionRun_862f {
  strings:
    $key_862f = { d5 40 [2] f1 4e [2] da 62 [2] f4 40 [2] e0 5b [2] ef 41 [2] f1 5c [2] f3 5d [2] e8 5b [2] f4 5c [2] e8 73 }

  condition:
    any of them
}