rule TTP_XOR_QUAD_CurrentVersionRun_e618 {
  strings:
    $key_e618 = { b5 77 [2] 91 79 [2] ba 55 [2] 94 77 [2] 80 6c [2] 8f 76 [2] 91 6b [2] 93 6a [2] 88 6c [2] 94 6b [2] 88 44 }

  condition:
    any of them
}