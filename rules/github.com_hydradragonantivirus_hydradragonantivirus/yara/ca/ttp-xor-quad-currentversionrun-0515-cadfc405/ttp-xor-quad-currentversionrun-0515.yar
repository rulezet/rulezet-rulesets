rule TTP_XOR_QUAD_CurrentVersionRun_0515 {
  strings:
    $key_0515 = { 56 7a [2] 72 74 [2] 59 58 [2] 77 7a [2] 63 61 [2] 6c 7b [2] 72 66 [2] 70 67 [2] 6b 61 [2] 77 66 [2] 6b 49 }

  condition:
    any of them
}