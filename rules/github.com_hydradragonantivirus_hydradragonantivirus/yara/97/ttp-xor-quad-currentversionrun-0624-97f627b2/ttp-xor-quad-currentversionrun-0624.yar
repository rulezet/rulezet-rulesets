rule TTP_XOR_QUAD_CurrentVersionRun_0624 {
  strings:
    $key_0624 = { 55 4b [2] 71 45 [2] 5a 69 [2] 74 4b [2] 60 50 [2] 6f 4a [2] 71 57 [2] 73 56 [2] 68 50 [2] 74 57 [2] 68 78 }

  condition:
    any of them
}