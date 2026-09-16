rule TTP_XOR_QUAD_CurrentVersionRun_6bf8 {
  strings:
    $key_6bf8 = { 38 97 [2] 1c 99 [2] 37 b5 [2] 19 97 [2] 0d 8c [2] 02 96 [2] 1c 8b [2] 1e 8a [2] 05 8c [2] 19 8b [2] 05 a4 }

  condition:
    any of them
}