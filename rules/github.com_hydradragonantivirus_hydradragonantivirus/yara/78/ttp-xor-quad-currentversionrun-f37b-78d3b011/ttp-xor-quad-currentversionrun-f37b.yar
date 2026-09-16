rule TTP_XOR_QUAD_CurrentVersionRun_f37b {
  strings:
    $key_f37b = { a0 14 [2] 84 1a [2] af 36 [2] 81 14 [2] 95 0f [2] 9a 15 [2] 84 08 [2] 86 09 [2] 9d 0f [2] 81 08 [2] 9d 27 }

  condition:
    any of them
}