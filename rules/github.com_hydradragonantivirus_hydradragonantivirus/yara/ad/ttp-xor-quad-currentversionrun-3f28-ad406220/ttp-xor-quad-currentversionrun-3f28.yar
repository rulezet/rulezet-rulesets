rule TTP_XOR_QUAD_CurrentVersionRun_3f28 {
  strings:
    $key_3f28 = { 6c 47 [2] 48 49 [2] 63 65 [2] 4d 47 [2] 59 5c [2] 56 46 [2] 48 5b [2] 4a 5a [2] 51 5c [2] 4d 5b [2] 51 74 }

  condition:
    any of them
}