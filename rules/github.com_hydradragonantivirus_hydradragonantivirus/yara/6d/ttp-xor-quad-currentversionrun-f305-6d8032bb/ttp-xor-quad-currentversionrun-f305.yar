rule TTP_XOR_QUAD_CurrentVersionRun_f305 {
  strings:
    $key_f305 = { a0 6a [2] 84 64 [2] af 48 [2] 81 6a [2] 95 71 [2] 9a 6b [2] 84 76 [2] 86 77 [2] 9d 71 [2] 81 76 [2] 9d 59 }

  condition:
    any of them
}