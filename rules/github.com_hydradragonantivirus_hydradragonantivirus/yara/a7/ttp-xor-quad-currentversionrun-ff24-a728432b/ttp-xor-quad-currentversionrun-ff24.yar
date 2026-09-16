rule TTP_XOR_QUAD_CurrentVersionRun_ff24 {
  strings:
    $key_ff24 = { ac 4b [2] 88 45 [2] a3 69 [2] 8d 4b [2] 99 50 [2] 96 4a [2] 88 57 [2] 8a 56 [2] 91 50 [2] 8d 57 [2] 91 78 }

  condition:
    any of them
}