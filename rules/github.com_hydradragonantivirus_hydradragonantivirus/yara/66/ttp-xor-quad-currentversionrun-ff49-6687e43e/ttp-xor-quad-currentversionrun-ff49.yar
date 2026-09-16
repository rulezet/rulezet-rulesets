rule TTP_XOR_QUAD_CurrentVersionRun_ff49 {
  strings:
    $key_ff49 = { ac 26 [2] 88 28 [2] a3 04 [2] 8d 26 [2] 99 3d [2] 96 27 [2] 88 3a [2] 8a 3b [2] 91 3d [2] 8d 3a [2] 91 15 }

  condition:
    any of them
}