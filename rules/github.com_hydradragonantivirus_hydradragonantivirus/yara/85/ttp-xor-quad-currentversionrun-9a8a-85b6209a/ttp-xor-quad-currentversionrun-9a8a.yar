rule TTP_XOR_QUAD_CurrentVersionRun_9a8a {
  strings:
    $key_9a8a = { c9 e5 [2] ed eb [2] c6 c7 [2] e8 e5 [2] fc fe [2] f3 e4 [2] ed f9 [2] ef f8 [2] f4 fe [2] e8 f9 [2] f4 d6 }

  condition:
    any of them
}