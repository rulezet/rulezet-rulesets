rule TTP_XOR_QUAD_CurrentVersionRun_ffea {
  strings:
    $key_ffea = { ac 85 [2] 88 8b [2] a3 a7 [2] 8d 85 [2] 99 9e [2] 96 84 [2] 88 99 [2] 8a 98 [2] 91 9e [2] 8d 99 [2] 91 b6 }

  condition:
    any of them
}