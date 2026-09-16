rule TTP_XOR_QUAD_CurrentVersionRun_f228 {
  strings:
    $key_f228 = { a1 47 [2] 85 49 [2] ae 65 [2] 80 47 [2] 94 5c [2] 9b 46 [2] 85 5b [2] 87 5a [2] 9c 5c [2] 80 5b [2] 9c 74 }

  condition:
    any of them
}