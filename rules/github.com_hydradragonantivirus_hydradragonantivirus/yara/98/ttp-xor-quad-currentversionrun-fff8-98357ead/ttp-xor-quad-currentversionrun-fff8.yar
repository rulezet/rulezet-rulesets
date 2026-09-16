rule TTP_XOR_QUAD_CurrentVersionRun_fff8 {
  strings:
    $key_fff8 = { ac 97 [2] 88 99 [2] a3 b5 [2] 8d 97 [2] 99 8c [2] 96 96 [2] 88 8b [2] 8a 8a [2] 91 8c [2] 8d 8b [2] 91 a4 }

  condition:
    any of them
}