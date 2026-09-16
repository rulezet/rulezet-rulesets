rule TTP_XOR_QUAD_CurrentVersionRun_ff17 {
  strings:
    $key_ff17 = { ac 78 [2] 88 76 [2] a3 5a [2] 8d 78 [2] 99 63 [2] 96 79 [2] 88 64 [2] 8a 65 [2] 91 63 [2] 8d 64 [2] 91 4b }

  condition:
    any of them
}