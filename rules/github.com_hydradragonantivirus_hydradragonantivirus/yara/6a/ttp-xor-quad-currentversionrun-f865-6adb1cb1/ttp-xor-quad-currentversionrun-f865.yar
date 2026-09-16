rule TTP_XOR_QUAD_CurrentVersionRun_f865 {
  strings:
    $key_f865 = { ab 0a [2] 8f 04 [2] a4 28 [2] 8a 0a [2] 9e 11 [2] 91 0b [2] 8f 16 [2] 8d 17 [2] 96 11 [2] 8a 16 [2] 96 39 }

  condition:
    any of them
}