rule TTP_XOR_QUAD_CurrentVersionRun_3a15 {
  strings:
    $key_3a15 = { 69 7a [2] 4d 74 [2] 66 58 [2] 48 7a [2] 5c 61 [2] 53 7b [2] 4d 66 [2] 4f 67 [2] 54 61 [2] 48 66 [2] 54 49 }

  condition:
    any of them
}