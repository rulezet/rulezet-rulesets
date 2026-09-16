rule TTP_XOR_QUAD_CurrentVersionRun_3f08 {
  strings:
    $key_3f08 = { 6c 67 [2] 48 69 [2] 63 45 [2] 4d 67 [2] 59 7c [2] 56 66 [2] 48 7b [2] 4a 7a [2] 51 7c [2] 4d 7b [2] 51 54 }

  condition:
    any of them
}