rule TTP_XOR_QUAD_CurrentVersionRun_f328 {
  strings:
    $key_f328 = { a0 47 [2] 84 49 [2] af 65 [2] 81 47 [2] 95 5c [2] 9a 46 [2] 84 5b [2] 86 5a [2] 9d 5c [2] 81 5b [2] 9d 74 }

  condition:
    any of them
}