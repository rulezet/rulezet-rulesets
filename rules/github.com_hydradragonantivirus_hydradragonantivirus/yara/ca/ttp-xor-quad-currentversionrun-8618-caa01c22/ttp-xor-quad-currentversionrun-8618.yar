rule TTP_XOR_QUAD_CurrentVersionRun_8618 {
  strings:
    $key_8618 = { d5 77 [2] f1 79 [2] da 55 [2] f4 77 [2] e0 6c [2] ef 76 [2] f1 6b [2] f3 6a [2] e8 6c [2] f4 6b [2] e8 44 }

  condition:
    any of them
}