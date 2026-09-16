rule TTP_XOR_QUAD_CurrentVersionRun_fffb {
  strings:
    $key_fffb = { ac 94 [2] 88 9a [2] a3 b6 [2] 8d 94 [2] 99 8f [2] 96 95 [2] 88 88 [2] 8a 89 [2] 91 8f [2] 8d 88 [2] 91 a7 }

  condition:
    any of them
}