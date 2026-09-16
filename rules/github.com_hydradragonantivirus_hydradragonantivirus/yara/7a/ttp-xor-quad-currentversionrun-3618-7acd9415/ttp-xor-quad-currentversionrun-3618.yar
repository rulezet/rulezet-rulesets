rule TTP_XOR_QUAD_CurrentVersionRun_3618 {
  strings:
    $key_3618 = { 65 77 [2] 41 79 [2] 6a 55 [2] 44 77 [2] 50 6c [2] 5f 76 [2] 41 6b [2] 43 6a [2] 58 6c [2] 44 6b [2] 58 44 }

  condition:
    any of them
}