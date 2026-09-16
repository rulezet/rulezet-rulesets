rule TTP_XOR_QUAD_CurrentVersionRun_3505 {
  strings:
    $key_3505 = { 66 6a [2] 42 64 [2] 69 48 [2] 47 6a [2] 53 71 [2] 5c 6b [2] 42 76 [2] 40 77 [2] 5b 71 [2] 47 76 [2] 5b 59 }

  condition:
    any of them
}