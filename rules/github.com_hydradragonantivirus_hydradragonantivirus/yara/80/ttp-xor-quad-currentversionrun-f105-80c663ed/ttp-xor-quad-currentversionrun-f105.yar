rule TTP_XOR_QUAD_CurrentVersionRun_f105 {
  strings:
    $key_f105 = { a2 6a [2] 86 64 [2] ad 48 [2] 83 6a [2] 97 71 [2] 98 6b [2] 86 76 [2] 84 77 [2] 9f 71 [2] 83 76 [2] 9f 59 }

  condition:
    any of them
}