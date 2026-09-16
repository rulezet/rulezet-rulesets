rule TTP_XOR_QUAD_CurrentVersionRun_3c18 {
  strings:
    $key_3c18 = { 6f 77 [2] 4b 79 [2] 60 55 [2] 4e 77 [2] 5a 6c [2] 55 76 [2] 4b 6b [2] 49 6a [2] 52 6c [2] 4e 6b [2] 52 44 }

  condition:
    any of them
}