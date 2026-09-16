rule TTP_XOR_QUAD_CurrentVersionRun_3915 {
  strings:
    $key_3915 = { 6a 7a [2] 4e 74 [2] 65 58 [2] 4b 7a [2] 5f 61 [2] 50 7b [2] 4e 66 [2] 4c 67 [2] 57 61 [2] 4b 66 [2] 57 49 }

  condition:
    any of them
}