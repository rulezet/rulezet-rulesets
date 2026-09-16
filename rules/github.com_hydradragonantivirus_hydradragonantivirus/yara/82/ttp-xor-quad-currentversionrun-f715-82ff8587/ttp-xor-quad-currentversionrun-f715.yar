rule TTP_XOR_QUAD_CurrentVersionRun_f715 {
  strings:
    $key_f715 = { a4 7a [2] 80 74 [2] ab 58 [2] 85 7a [2] 91 61 [2] 9e 7b [2] 80 66 [2] 82 67 [2] 99 61 [2] 85 66 [2] 99 49 }

  condition:
    any of them
}