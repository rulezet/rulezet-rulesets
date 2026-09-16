rule TTP_XOR_QUAD_CurrentVersionRun_1618 {
  strings:
    $key_1618 = { 45 77 [2] 61 79 [2] 4a 55 [2] 64 77 [2] 70 6c [2] 7f 76 [2] 61 6b [2] 63 6a [2] 78 6c [2] 64 6b [2] 78 44 }

  condition:
    any of them
}