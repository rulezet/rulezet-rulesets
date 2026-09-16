rule TTP_XOR_QUAD_CurrentVersionRun_6be5 {
  strings:
    $key_6be5 = { 38 8a [2] 1c 84 [2] 37 a8 [2] 19 8a [2] 0d 91 [2] 02 8b [2] 1c 96 [2] 1e 97 [2] 05 91 [2] 19 96 [2] 05 b9 }

  condition:
    any of them
}