rule TTP_XOR_QUAD_CurrentVersionRun_ffeb {
  strings:
    $key_ffeb = { ac 84 [2] 88 8a [2] a3 a6 [2] 8d 84 [2] 99 9f [2] 96 85 [2] 88 98 [2] 8a 99 [2] 91 9f [2] 8d 98 [2] 91 b7 }

  condition:
    any of them
}