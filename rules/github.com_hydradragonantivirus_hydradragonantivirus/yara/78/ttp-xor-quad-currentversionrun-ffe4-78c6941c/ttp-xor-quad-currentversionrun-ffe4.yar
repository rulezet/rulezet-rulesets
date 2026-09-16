rule TTP_XOR_QUAD_CurrentVersionRun_ffe4 {
  strings:
    $key_ffe4 = { ac 8b [2] 88 85 [2] a3 a9 [2] 8d 8b [2] 99 90 [2] 96 8a [2] 88 97 [2] 8a 96 [2] 91 90 [2] 8d 97 [2] 91 b8 }

  condition:
    any of them
}