rule TTP_XOR_QUAD_CurrentVersionRun_f805 {
  strings:
    $key_f805 = { ab 6a [2] 8f 64 [2] a4 48 [2] 8a 6a [2] 9e 71 [2] 91 6b [2] 8f 76 [2] 8d 77 [2] 96 71 [2] 8a 76 [2] 96 59 }

  condition:
    any of them
}