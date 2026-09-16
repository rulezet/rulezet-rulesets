rule TTP_XOR_QUAD_CurrentVersionRun_6b24 {
  strings:
    $key_6b24 = { 38 4b [2] 1c 45 [2] 37 69 [2] 19 4b [2] 0d 50 [2] 02 4a [2] 1c 57 [2] 1e 56 [2] 05 50 [2] 19 57 [2] 05 78 }

  condition:
    any of them
}