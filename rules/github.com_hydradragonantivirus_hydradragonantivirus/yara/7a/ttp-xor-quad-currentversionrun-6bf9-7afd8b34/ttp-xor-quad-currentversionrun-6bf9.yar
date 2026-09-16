rule TTP_XOR_QUAD_CurrentVersionRun_6bf9 {
  strings:
    $key_6bf9 = { 38 96 [2] 1c 98 [2] 37 b4 [2] 19 96 [2] 0d 8d [2] 02 97 [2] 1c 8a [2] 1e 8b [2] 05 8d [2] 19 8a [2] 05 a5 }

  condition:
    any of them
}