rule TTP_XOR_QUAD_CurrentVersionRun_f028 {
  strings:
    $key_f028 = { a3 47 [2] 87 49 [2] ac 65 [2] 82 47 [2] 96 5c [2] 99 46 [2] 87 5b [2] 85 5a [2] 9e 5c [2] 82 5b [2] 9e 74 }

  condition:
    any of them
}