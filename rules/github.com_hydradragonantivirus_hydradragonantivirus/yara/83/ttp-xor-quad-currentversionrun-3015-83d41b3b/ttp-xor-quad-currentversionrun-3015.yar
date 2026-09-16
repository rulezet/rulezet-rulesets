rule TTP_XOR_QUAD_CurrentVersionRun_3015 {
  strings:
    $key_3015 = { 63 7a [2] 47 74 [2] 6c 58 [2] 42 7a [2] 56 61 [2] 59 7b [2] 47 66 [2] 45 67 [2] 5e 61 [2] 42 66 [2] 5e 49 }

  condition:
    any of them
}