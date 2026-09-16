rule TTP_XOR_QUAD_CurrentVersionRun_0a08 {
  strings:
    $key_0a08 = { 59 67 [2] 7d 69 [2] 56 45 [2] 78 67 [2] 6c 7c [2] 63 66 [2] 7d 7b [2] 7f 7a [2] 64 7c [2] 78 7b [2] 64 54 }

  condition:
    any of them
}